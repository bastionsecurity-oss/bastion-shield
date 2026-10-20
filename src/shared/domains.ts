// Bastion Shield — a domain name as a user or a policy writes it (the nerd
// mode protected domains): shared by the dashboard, which says which lines it
// could not read, and the service worker, which keeps only valid entries.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/** Hostname syntax: dot-separated labels of letters, digits and hyphens, a last label of two or more. */
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

/**
 * `raw` as a domain: lower-cased, scheme, path, port and a leading "www."
 * removed, an IDN in punycode. Null when it is no domain name (an IP
 * address is none either).
 */
export function normalizeDomain(raw: string): string | null {
  let d = raw.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/:?#].*$/, '').replace(/\.$/, '');
  if (d === '') return null;
  try {
    d = new URL(`https://${d}`).hostname;
  } catch {
    // keep d: the syntax check below rejects it
  }
  d = d.replace(/^www\./, '');
  if (/^[0-9.]+$/.test(d)) return null;
  return DOMAIN_RE.test(d) ? d : null;
}
