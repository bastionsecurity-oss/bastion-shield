// Bastion Shield e2e — hostnames used by the fixture pages.
//
// The fixture sites live under the IANA-reserved example.com / .net / .org
// names. Those TLDs are on the Public Suffix List, so Chromium's eTLD+1 logic
// (DNR domainType, site isolation, third-party checks) treats them exactly
// like real sites: site-a.example.com and cdn.example.com are same-site,
// site-a.example.com and site-b.example.net are cross-site. A made-up TLD such
// as ".example" has no registrable domain and would make every host its own
// "site", which hides first-party bugs.
//
// Chromium is started with `--host-resolver-rules=MAP * 127.0.0.1:<port>`, so
// every hostname and port, including real ad-server names taken from the
// shipped lists, connects to the local fixture server and nothing leaves the
// machine. Fixture URLs therefore carry no port, exactly like real ones: an
// explicit ":port" would stop path-anchored filters such as
// `||host/path$redirect=...` from matching and let broader `||host^` blocks win.
//
// SPDX-License-Identifier: GPL-3.0-or-later

export const HOSTS = {
  /** Main first-party test site. */
  A: 'site-a.example.com',
  /** Same-site subdomain of A (first party for DNR). */
  A_SUB: 'static.example.com',
  /** Second, cross-site test site. */
  B: 'site-b.example.net',
  /** Third, cross-site test site. */
  C: 'site-c.example.org',
  /** Neutral third-party CDN that no list blocks. */
  CDN: 'cdn.example.net',
} as const;

/** Well-known ad/tracker endpoints that every Brave-equivalent list stack blocks. */
export const KNOWN_TRACKERS: { host: string; path: string; kind: 'script' | 'img' | 'fetch' }[] = [
  { host: 'securepubads.g.doubleclick.net', path: '/tag/js/gpt.js', kind: 'script' },
  { host: 'www.google-analytics.com', path: '/analytics.js', kind: 'script' },
  { host: 'connect.facebook.net', path: '/en_US/fbevents.js', kind: 'script' },
  { host: 'pagead2.googlesyndication.com', path: '/pagead/js/adsbygoogle.js', kind: 'script' },
  { host: 'ad.doubleclick.net', path: '/ddm/trackimp/pixel.gif', kind: 'img' },
];

/** Chromium switches that send every connection to the fixture server and keep fixture URLs as written. */
export function hermeticArgs(port: number): string[] {
  return [
    `--host-resolver-rules=MAP * 127.0.0.1:${port}`,
    '--ignore-certificate-errors',
    // No --disable-features here: Chromium honours only the last occurrence of
    // that switch, so it would silently replace Playwright's own list. Fixture
    // URLs are https:// on loopback, so HTTPS upgrades and local-network
    // checks do not get in the way anyway.
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-sync',
    '--metrics-recording-only',
  ];
}
