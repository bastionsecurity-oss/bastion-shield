## Measured results

Run 2026-10-18 16:59 UTC on win32 10.0.26200, 16 × AMD Ryzen 7 9800X3D 8-Core Processor, 64 GB RAM.
- **Chromium**: Chrome/156.0.8078.4 (headless)
- **Bastion**: Chrome/156.0.8078.4 (headless), Bastion Shield 0.1.0.2900 — blocking active after 0 s
- **Brave**: Chrome/155.0.8059.85 (headless) — blocking active after 12 s
- Reference set: 56'377 ad/tracker hostnames (EasyList 202610181630, EasyPrivacy 202610181630): EasyList adservers + EasyPrivacy trackingservers sections, `||host^` entries only.
- Each home page is loaded once per browser in a fresh profile, then observed for 15 s after the load event. Consent banners are not clicked, so this measures the first-visit state.
- Headless browsers present their regular user agent (the "HeadlessChrome" token is replaced): several sites reset the connection for headless clients otherwise.

### Ad/tracker requests that got through (third-party, host in reference set)

| Site | Requests (Chromium / Bastion / Brave) | Ad/tracker through (Chromium / Bastion / Brave) | Blocked (Chromium / Bastion / Brave) | DOMContentLoaded ms (Chromium / Bastion / Brave) | Load ms (Chromium / Bastion / Brave) | JS heap MB (Chromium / Bastion / Brave) |
|---|---|---|---|---|---|---|
| 20min.ch | 249 / 230 / 225 | 13 / 1 / 1 | 0 / 18 / 18 | 292 / 263 / 210 | 1'014 / 1'074 / 2'582 | 64.4 / 42.1 / 65.6 |
| blick.ch | 63 / 108 / 108 | 1 / 0 / 0 | 0 / 8 / 8 | 285 / 241 / 461 | 293 / 276 / 485 | 24.9 / 40.5 / 38.7 |
| watson.ch | 92 / 92 / 93 | 6 / 1 / 1 | 0 / 11 / 11 | 302 / 313 / 3'315 | 616 / 355 / 9'447 | 16.5 / 8.4 / 7.7 |
| nzz.ch | 170 / 116 / 126 | 16 / 0 / 0 | 0 / 17 / 23 | 247 / 173 / 202 | 734 / 393 / 352 | 35.5 / 22.8 / 21.9 |
| tagesanzeiger.ch | 287 / 210 / 212 | 60 / 0 / 0 | 0 / 11 / 11 | 399 / 461 / 393 | 693 / 462 / 394 | 24.4 / 7.1 / 6.1 |
| srf.ch | 115 / 108 / 108 | 11 / 0 / 0 | 0 / 13 / 13 | 223 / 257 / 260 | 614 / 349 / 426 | 7.3 / 8.2 / 9.1 |
| letemps.ch | 158 / 140 / 142 | 7 / 0 / 0 | 0 / 16 / 15 | 376 / 458 / 435 | 870 / 564 / 585 | 20.8 / 13.3 / 11.3 |
| rts.ch | 168 / 153 / 155 | 12 / 0 / 0 | 0 / 17 / 17 | 223 / 276 / 231 | 297 / 348 / 277 | 11.7 / 8.5 / 12.6 |
| rsi.ch | 126 / 99 / 99 | 6 / 0 / 0 | 0 / 8 / 8 | 323 / 233 / 248 | 352 / 251 / 273 | 19.2 / 15.2 / 18.4 |
| ricardo.ch | 134 / 86 / 86 | 37 / 0 / 0 | 0 / 11 / 11 | 1'250 / 682 / 691 | 1'880 / 1'184 / 1'143 | 50.6 / 38.1 / 35.0 |
| tutti.ch | 92 / 62 / 62 | 19 / 0 / 0 | 0 / 5 / 5 | 570 / 350 / 335 | 575 / 374 / 347 | 30.4 / 18.6 / 18.0 |
| digitec.ch | 242 / 235 / 239 | 2 / 0 / 0 | 0 / 1 / 1 | 564 / 616 / 483 | 633 / 686 / 520 | 43.2 / 40.6 / 32.9 |
| galaxus.ch | 248 / 281 / 282 | 2 / 0 / 0 | 0 / 1 / 1 | 818 / 574 / 528 | 884 / 642 / 529 | 32.5 / 22.1 / 21.6 |
| local.ch | 131 / 107 / 111 | 12 / 0 / 0 | 0 / 6 / 6 | 136 / 106 / 124 | 399 / 367 / 282 | 21.4 / 11.7 / 14.4 |
| search.ch | 53 / 23 / 23 | 13 / 0 / 0 | 0 / 2 / 2 | 133 / 139 / 135 | 494 / 155 / 148 | 20.0 / 4.2 / 3.7 |
| cnn.com | 134 / 107 / 113 | 21 / 0 / 0 | 0 / 13 / 13 | 491 / 502 / 468 | 800 / 749 / 660 | 36.3 / 29.4 / 34.0 |
| theguardian.com | 107 / 123 / 123 | 0 / 0 / 0 | 0 / 1 / 1 | 107 / 224 / 118 | 359 / 382 / 296 | 10.1 / 16.1 / 14.3 |
| spiegel.de | 47 / 75 / 73 | 0 / 0 / 0 | 0 / 14 / 13 | 276 / 331 / 305 | 568 / 645 / 531 | 14.6 / 13.3 / 19.6 |
| bild.de | 260 / 464 / 459 | 0 / 0 / 0 | 0 / 27 / 27 | 283 / 305 / 259 | 697 / 719 / 846 | 24.7 / 50.9 / 49.4 |
| lemonde.fr | 51 / 48 / 49 | 2 / 0 / 0 | 0 / 4 / 4 | 310 / 337 / 309 | 422 / 436 / 424 | 5.8 / 7.7 / 8.7 |
| corriere.it | 363 / 637 / 628 | 42 / 0 / 0 | 0 / 107 / 89 | 213 / 289 / 183 | 1'519 / 1'310 / 1'744 | 29.2 / 31.8 / 27.8 |
| youtube.com | 171 / 274 / 286 | 0 / 0 / 0 | 0 / 2 / 10 | 696 / 753 / 647 | 877 / 789 / 688 | 73.9 / 46.2 / 45.6 |
| reddit.com | 152 / 124 / 125 | 0 / 0 / 0 | 0 / 2 / 2 | 536 / 547 / 536 | 865 / 553 / 871 | 28.0 / 29.6 / 30.2 |
| stackoverflow.com | 113 / 1'677 / 74 | 25 / 0 / 0 | 0 / 5 / 5 | 25 / 43 / 45 | 83 / 123 / 111 | 28.2 / 8.2 / 13.6 |
| weather.com | 177 / 331 / 321 | 29 / 6 / 6 | 0 / 93 / 81 | 237 / 205 / 217 | 981 / 708 / 748 | 35.6 / 39.6 / 28.1 |
| **Total / median** | 3'903 / 5'910 / 4'322 | 336 / 8 / 8 | 0 / 413 / 395 | 292 / 305 / 305 | 633 / 462 / 520 | 24.9 / 18.6 / 19.6 |

Reduction of ad/tracker requests that got through, relative to plain Chromium: Bastion 97.6 %, Brave 97.6 %.

Bastion service worker JS heap right after the load event: median 1.9 MB, max 3.1 MB (25 visits). At the end of the visit the SW was already stopped by Chromium (idle) in 0 of 25 visits; when still running: median 2.2 MB.

### Ad/tracker hosts that got through in Bastion but not in Brave

- none

### Ad/tracker hosts that got through in Brave but not in Bastion

- none

### REA cross-check

REA 6.7.0 (`rea inspect-web-page --observation-ms 8000`) attached to each browser's loopback CDP endpoint after the load event. REA scopes captures to the origins passed with --allowed-origins (here: every origin our CDP capture saw); its network section only covers its own observation window, its resource inventory covers everything the frames loaded.

Columns: ad/tracker entries in REA's resource inventory; how many had content; how many of those our CDP capture identified as neutered stubs (REA sees the stub under the original URL, e.g. a 5 KB gpt.js); entries REA lists without content (blocked or failed requests, also 204 beacons); disagreements = content per REA but hard-blocked per CDP; hosts REA saw that our capture missed.

| Site | Browser | REA | Resources | Ad/tracker entries | with content | confirmed stubs | no content | disagreements | missed by CDP |
|---|---|---|---|---|---|---|---|---|---|
| 20min.ch | Chromium | ok | 84 | 6 | 5 | 0 | 1 | 0 | 0 |
| 20min.ch | Bastion | ok | 73 | 1 | 1 | 0 | 0 | 0 | 0 |
| 20min.ch | Brave | ok | 76 | 5 | 4 | 3 | 1 | 0 | 0 |
| blick.ch | Chromium | ok | 48 | 0 | 0 | 0 | 0 | 0 | 0 |
| blick.ch | Bastion | ok | 55 | 0 | 0 | 0 | 0 | 0 | 0 |
| blick.ch | Brave | ok | 57 | 1 | 1 | 1 | 0 | 0 | 0 |
| watson.ch | Chromium | ok | 71 | 4 | 4 | 0 | 0 | 0 | 0 |
| watson.ch | Bastion | ok | 68 | 1 | 1 | 0 | 0 | 0 | 0 |
| watson.ch | Brave | ok | 72 | 4 | 4 | 3 | 0 | 0 | 0 |
| nzz.ch | Chromium | ok | 113 | 6 | 6 | 0 | 0 | 0 | 0 |
| nzz.ch | Bastion | ok | 74 | 2 | 0 | 0 | 2 | 0 | 0 |
| nzz.ch | Brave | ok | 85 | 2 | 0 | 0 | 2 | 0 | 0 |
| tagesanzeiger.ch | Chromium | ok | 136 | 11 | 11 | 0 | 0 | 0 | 0 |
| tagesanzeiger.ch | Bastion | ok | 121 | 1 | 0 | 0 | 1 | 0 | 0 |
| tagesanzeiger.ch | Brave | ok | 127 | 3 | 1 | 1 | 2 | 0 | 0 |
| srf.ch | Chromium | ok | 79 | 4 | 4 | 0 | 0 | 0 | 0 |
| srf.ch | Bastion | ok | 76 | 1 | 0 | 0 | 1 | 0 | 0 |
| srf.ch | Brave | ok | 93 | 4 | 2 | 2 | 2 | 0 | 0 |
| letemps.ch | Chromium | ok | 145 | 5 | 5 | 0 | 0 | 0 | 0 |
| letemps.ch | Bastion | ok | 116 | 1 | 0 | 0 | 1 | 0 | 0 |
| letemps.ch | Brave | ok | 117 | 2 | 1 | 1 | 1 | 0 | 0 |
| rts.ch | Chromium | ok | 62 | 5 | 5 | 0 | 0 | 0 | 0 |
| rts.ch | Bastion | ok | 57 | 0 | 0 | 0 | 0 | 0 | 0 |
| rts.ch | Brave | ok | 53 | 3 | 3 | 3 | 0 | 0 | 0 |
| rsi.ch | Chromium | ok | 84 | 3 | 3 | 0 | 0 | 0 | 0 |
| rsi.ch | Bastion | ok | 73 | 0 | 0 | 0 | 0 | 0 | 0 |
| rsi.ch | Brave | ok | 87 | 1 | 1 | 1 | 0 | 0 | 0 |
| ricardo.ch | Chromium | ok | 80 | 11 | 11 | 0 | 0 | 0 | 0 |
| ricardo.ch | Bastion | ok | 68 | 1 | 1 | 1 | 0 | 0 | 0 |
| ricardo.ch | Brave | ok | 69 | 2 | 2 | 2 | 0 | 0 | 0 |
| tutti.ch | Chromium | ok | 57 | 5 | 5 | 0 | 0 | 0 | 0 |
| tutti.ch | Bastion | ok | 49 | 0 | 0 | 0 | 0 | 0 | 0 |
| tutti.ch | Brave | ok | 51 | 2 | 2 | 2 | 0 | 0 | 0 |
| digitec.ch | Chromium | ok | 182 | 2 | 2 | 0 | 0 | 0 | 0 |
| digitec.ch | Bastion | ok | 177 | 0 | 0 | 0 | 0 | 0 | 0 |
| digitec.ch | Brave | ok | 182 | 1 | 1 | 1 | 0 | 0 | 0 |
| galaxus.ch | Chromium | ok | 188 | 2 | 2 | 0 | 0 | 0 | 0 |
| galaxus.ch | Bastion | ok | 178 | 0 | 0 | 0 | 0 | 0 | 0 |
| galaxus.ch | Brave | ok | 180 | 1 | 1 | 1 | 0 | 0 | 0 |
| local.ch | Chromium | ok | 69 | 5 | 4 | 0 | 1 | 0 | 0 |
| local.ch | Bastion | ok | 59 | 0 | 0 | 0 | 0 | 0 | 0 |
| local.ch | Brave | ok | 63 | 3 | 1 | 1 | 2 | 0 | 0 |
| search.ch | Chromium | ok | 34 | 9 | 9 | 0 | 0 | 0 | 0 |
| search.ch | Bastion | ok | 20 | 1 | 1 | 1 | 0 | 0 | 0 |
| search.ch | Brave | ok | 20 | 1 | 1 | 1 | 0 | 0 | 0 |
| cnn.com | Chromium | ok | 73 | 10 | 10 | 0 | 0 | 0 | 0 |
| cnn.com | Bastion | ok | 58 | 0 | 0 | 0 | 0 | 0 | 0 |
| cnn.com | Brave | ok | 60 | 0 | 0 | 0 | 0 | 0 | 0 |
| theguardian.com | Chromium | ok | 81 | 0 | 0 | 0 | 0 | 0 | 0 |
| theguardian.com | Bastion | ok | 85 | 1 | 0 | 0 | 1 | 0 | 0 |
| theguardian.com | Brave | ok | 86 | 1 | 0 | 0 | 1 | 0 | 0 |
| spiegel.de | Chromium | ok | 28 | 0 | 0 | 0 | 0 | 0 | 0 |
| spiegel.de | Bastion | ok | 43 | 8 | 1 | 1 | 7 | 0 | 0 |
| spiegel.de | Brave | ok | 37 | 7 | 7 | 7 | 0 | 0 | 0 |
| bild.de | Chromium | ok | 205 | 0 | 0 | 0 | 0 | 0 | 0 |
| bild.de | Bastion | ok | 338 | 0 | 0 | 0 | 0 | 0 | 0 |
| bild.de | Brave | ok | 342 | 2 | 2 | 2 | 0 | 0 | 0 |
| lemonde.fr | Chromium | ok | 34 | 0 | 0 | 0 | 0 | 0 | 0 |
| lemonde.fr | Bastion | ok | 33 | 0 | 0 | 0 | 0 | 0 | 0 |
| lemonde.fr | Brave | ok | 36 | 0 | 0 | 0 | 0 | 0 | 0 |
| corriere.it | Chromium | ok | 213 | 18 | 18 | 0 | 0 | 0 | 0 |
| corriere.it | Bastion | ok | 219 | 7 | 4 | 4 | 3 | 0 | 0 |
| corriere.it | Brave | ok | 236 | 16 | 16 | 16 | 0 | 0 | 0 |
| youtube.com | Chromium | ok | 28 | 0 | 0 | 0 | 0 | 0 | 0 |
| youtube.com | Bastion | ok | 27 | 0 | 0 | 0 | 0 | 0 | 0 |
| youtube.com | Brave | ok | 26 | 0 | 0 | 0 | 0 | 0 | 0 |
| reddit.com | Chromium | ok | 61 | 0 | 0 | 0 | 0 | 0 | 0 |
| reddit.com | Bastion | ok | 61 | 0 | 0 | 0 | 0 | 0 | 0 |
| reddit.com | Brave | ok | 61 | 0 | 0 | 0 | 0 | 0 | 0 |
| stackoverflow.com | Chromium | ok | 64 | 4 | 4 | 0 | 0 | 0 | 0 |
| stackoverflow.com | Bastion | ok | 55 | 0 | 0 | 0 | 0 | 0 | 0 |
| stackoverflow.com | Brave | ok | 62 | 3 | 2 | 2 | 1 | 0 | 0 |
| weather.com | Chromium | ok | 92 | 9 | 9 | 0 | 0 | 0 | 0 |
| weather.com | Bastion | ok | 92 | 12 | 5 | 3 | 7 | 0 | 0 |
| weather.com | Brave | ok | 85 | 7 | 5 | 3 | 2 | 0 | 0 |

Raw data: `test/bench/results/2026-10-18*.json`.
