// Bastion Shield — estimate of data and waiting time saved by blocking.
// Nothing here is measured: a blocked request never loads, so its size and
// cost are unknown. We multiply blocked requests per resource type by typical
// values (HTTP Archive medians for third-party ad/tracker resources, rounded
// down) and always show the result as an estimate («ca.»).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { formatLocale } from './i18n.ts';

/** Typical transfer size in bytes per blocked request, by chrome.webRequest resource type. */
const BYTES: Record<string, number> = {
  script: 40_000,
  sub_frame: 60_000,
  image: 10_000,
  imageset: 10_000,
  media: 80_000,
  stylesheet: 12_000,
  font: 25_000,
  xmlhttprequest: 2_000,
  ping: 300,
  csp_report: 300,
  websocket: 0,
  main_frame: 0,
  other: 2_000,
};

/** Typical main-thread / network time in ms each blocked request would have cost. */
const MS: Record<string, number> = {
  script: 60,
  sub_frame: 120,
  image: 4,
  imageset: 4,
  media: 20,
  stylesheet: 8,
  font: 6,
  xmlhttprequest: 6,
  ping: 1,
  csp_report: 1,
  websocket: 0,
  main_frame: 0,
  other: 3,
};

export interface Savings {
  bytes: number;
  ms: number;
}

/** Estimate from counts per resource type. Unknown types count as "other". */
export function estimateSavings(byType: Record<string, number> | undefined | null): Savings {
  let bytes = 0;
  let ms = 0;
  if (!byType) return { bytes, ms };
  for (const [type, n] of Object.entries(byType)) {
    if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) continue;
    bytes += n * (BYTES[type] ?? BYTES.other);
    ms += n * (MS[type] ?? MS.other);
  }
  return { bytes, ms };
}

/**
 * Estimate for a page when only some requests carry a type (the popup sees the
 * latest events, but counts every block): scale the typed sample up to `total`.
 */
export function estimateFromSample(types: readonly string[], total: number): Savings {
  if (total <= 0) return { bytes: 0, ms: 0 };
  if (types.length === 0) return estimateSavings({ other: total });
  const byType: Record<string, number> = {};
  for (const ty of types) byType[ty] = (byType[ty] ?? 0) + 1;
  const sample = estimateSavings(byType);
  const f = total / types.length;
  return { bytes: sample.bytes * f, ms: sample.ms * f };
}

const nf = (digits: number): Intl.NumberFormat => new Intl.NumberFormat(formatLocale, { maximumFractionDigits: digits, minimumFractionDigits: digits });

/** "820 kB", "1.2 MB", "86 MB", "1.4 GB" (decimal units, like the browser shows). */
export function fmtBytes(bytes: number): { value: string; unit: string } {
  if (bytes >= 1e9) return { value: nf(1).format(bytes / 1e9), unit: 'GB' };
  if (bytes >= 1e7) return { value: nf(0).format(bytes / 1e6), unit: 'MB' };
  if (bytes >= 1e6) return { value: nf(1).format(bytes / 1e6), unit: 'MB' };
  return { value: nf(0).format(Math.max(0, Math.round(bytes / 1e3))), unit: 'kB' };
}

/** "0.4 s", "12 s", "4 Min.", "2.5 Std." – unit labels come from the caller's locale. */
export function fmtDuration(ms: number, units: { s: string; min: string; h: string }): { value: string; unit: string } {
  const s = ms / 1000;
  if (s < 10) return { value: nf(1).format(s), unit: units.s };
  if (s < 90) return { value: nf(0).format(s), unit: units.s };
  const min = s / 60;
  if (min < 90) return { value: nf(0).format(min), unit: units.min };
  return { value: nf(1).format(min / 60), unit: units.h };
}
