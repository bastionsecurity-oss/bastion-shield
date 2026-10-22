// Bastion Shield — the logic behind «Einstellungen» (views/settings.ts), free
// of DOM so node:test can cover it: documented defaults for «Alles
// zurücksetzen», backup validation and the file summary of the restore
// dialog (D03), and the protected-domain list with the line of every entry
// that was left out.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BackupFile, Settings } from '../../shared/types.ts';
import { normalizeDomain } from '../../shared/domains.ts';

/** As MAX_PROTECTED_DOMAINS in background/settings.ts. */
export const MAX_PROTECTED_DOMAINS = 200;

/** Documented defaults (src/shared/types.ts). Used by «Alles zurücksetzen». */
export function defaultSettings(): Settings {
  return {
    version: 1,
    defaultMode: 'standard',
    lists: {},
    privacy: {
      gpc: true,
      stripParams: true,
      debounce: true,
      deAmp: true,
      fingerprinting: 'standard',
      blockHyperlinkAuditing: true,
      webrtcPolicy: 'default',
      blockThirdPartyCookies: null,
      disablePrivacySandboxAds: true,
      clipboardGuard: true,
    },
    ui: { badge: true, activityLog: true, incidentCta: true, language: 'auto' },
    history: { enabled: true, retentionDays: 30 },
    nerd: { enabled: false, contextMenu: true, filterHistory: true, fingerprintMeter: true, lookalike: true, protectedDomains: [] },
  };
}

/** Minimal structural validation of an imported backup file. */
export function validateBackup(data: unknown): BackupFile | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Partial<BackupFile>;
  if (d.format !== 'bastion-shield-backup' || d.version !== 1) return null;
  if (!d.settings || typeof d.settings !== 'object' || (d.settings as Settings).version !== 1) return null;
  if (d.sites !== undefined && (typeof d.sites !== 'object' || d.sites === null || Array.isArray(d.sites))) return null;
  if (d.customFilters !== undefined && typeof d.customFilters !== 'string') return null;
  return { format: 'bastion-shield-backup', version: 1, exportedAt: String(d.exportedAt ?? ''), settings: d.settings as Settings, sites: d.sites ?? {}, customFilters: d.customFilters ?? '' };
}

/** What the restore dialog (D03) says about a backup file: when it was made, how many site exceptions and own filters it holds. */
export function backupSummary(b: BackupFile): { created: number | null; sites: number; filters: number } {
  const when = Date.parse(b.exportedAt);
  const filters = b.customFilters.split('\n').filter((l) => {
    const s = l.trim();
    return s !== '' && !s.startsWith('!') && !(s.startsWith('#') && !s.startsWith('##') && !s.startsWith('#@#'));
  }).length;
  return { created: Number.isFinite(when) ? when : null, sites: Object.keys(b.sites ?? {}).length, filters };
}

export interface ProtectedDomains {
  domains: string[];
  /** Entries that are not domain names, with their 1-based line. */
  invalid: { text: string; line: number }[];
}

/**
 * Protected domains typed one per line (also accepts commas and URLs),
 * normalised like the service worker does (normalizeDomain) and
 * deduplicated.
 */
export function parseProtectedDomains(text: string): ProtectedDomains {
  const domains: string[] = [];
  const invalid: { text: string; line: number }[] = [];
  text.split('\n').forEach((lineText, i) => {
    for (const raw of lineText.split(/[,;]+/)) {
      const s = raw.trim();
      if (s === '' || s.startsWith('#') || s.startsWith('!')) continue;
      const d = normalizeDomain(s);
      if (d === null) invalid.push({ text: s, line: i + 1 });
      else if (!domains.includes(d)) domains.push(d);
    }
  });
  return { domains, invalid };
}
