// Bastion Shield bench — result types and the Markdown summary
// (test/bench/results/summary.md, meant to be pasted into docs/PARITY.md
// "Measured results" by the docs owner).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BrowserKind } from './browsers.ts';
import type { SiteCapture } from './capture.ts';
import type { ReaSiteResult } from './rea.ts';

export type SiteSummary = Omit<SiteCapture, 'requests'> & {
  /** Ad/tracker requests only (full lists with --save-requests). */
  adTrackerRequests: { url: string; blocked: boolean; status: number | null; failed: string | null; type: string }[];
};

export interface BenchResults {
  tool: 'bastion-shield-bench';
  version: 1;
  startedAt: string;
  finishedAt: string;
  machine: { platform: string; release: string; cpus: number; cpuModel: string; memGb: number; node: string };
  options: Record<string, unknown>;
  browsers: Partial<Record<BrowserKind, { executable: string; product: string; headless: boolean; extensionId?: string; extensionVersion?: string; ready: boolean; readyNote: string; error?: string }>>;
  reference: { hosts: number; sources: { name: string; title: string; version: string; hosts: number; file: string }[] };
  rea: { enabled: boolean; version: string | null; argv: string[] | null; note: string };
  sites: {
    name: string;
    url: string;
    region: string;
    results: Partial<Record<BrowserKind, SiteSummary>>;
    rea: Partial<Record<BrowserKind, ReaSiteResult>>;
  }[];
}

const LABEL: Record<BrowserKind, string> = { chromium: 'Chromium', bastion: 'Bastion', brave: 'Brave' };

function fmt(n: number | null | undefined, unit = ''): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '–';
  return `${Math.round(n).toLocaleString('de-CH').replace(/[’’]/g, "'")}${unit}`;
}

function mb(n: number | null | undefined): string {
  return n === null || n === undefined ? '–' : (n / 1048576).toFixed(1);
}

function median(xs: number[]): number | null {
  const s = xs.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!s.length) return null;
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

export function summaryMarkdown(r: BenchResults): string {
  const kinds = (['chromium', 'bastion', 'brave'] as BrowserKind[]).filter((k) => r.browsers[k] && !r.browsers[k]!.error);
  const cell = (site: BenchResults['sites'][number], f: (s: SiteSummary) => string) =>
    kinds.map((k) => {
      const s = site.results[k];
      if (!s) return '–';
      if (!s.ok) return 'err';
      return f(s);
    }).join(' / ');
  const head = kinds.map((k) => LABEL[k]).join(' / ');
  const lines: string[] = [];
  lines.push(`## Measured results`);
  lines.push('');
  lines.push(`Run ${r.startedAt.slice(0, 16).replace('T', ' ')} UTC on ${r.machine.platform} ${r.machine.release}, ${r.machine.cpus} × ${r.machine.cpuModel}, ${r.machine.memGb} GB RAM.`);
  for (const k of kinds) {
    const b = r.browsers[k]!;
    lines.push(`- **${LABEL[k]}**: ${b.product || b.executable}${b.headless ? ' (headless)' : ' (headed)'}${b.extensionVersion ? `, Bastion Shield ${b.extensionVersion}` : ''}${b.readyNote ? ` — ${b.readyNote}` : ''}`);
  }
  for (const k of ['chromium', 'bastion', 'brave'] as BrowserKind[]) {
    if (r.browsers[k]?.error) lines.push(`- **${LABEL[k]}**: not measured (${r.browsers[k]!.error})`);
  }
  lines.push(`- Reference set: ${fmt(r.reference.hosts)} ad/tracker hostnames (${r.reference.sources.map((s) => `${s.title} ${s.version}`).join(', ')}): EasyList adservers + EasyPrivacy trackingservers sections, \`||host^\` entries only.`);
  lines.push(`- Each home page is loaded once per browser in a fresh profile, then observed for ${Math.round(Number(r.options.settleMs ?? 15000) / 1000)} s after the load event. Consent banners are not clicked, so this measures the first-visit state.`);
  lines.push(`- Headless browsers present their regular user agent (the "HeadlessChrome" token is replaced): several sites reset the connection for headless clients otherwise.`);
  const remeasured = r.options.remeasured as string[] | undefined;
  if (remeasured?.length) lines.push(`- Re-measured later and merged into this run: ${remeasured.join(', ')}.`);
  lines.push('');
  lines.push(`### Ad/tracker requests that got through (third-party, host in reference set)`);
  lines.push('');
  lines.push(`| Site | Requests (${head}) | Ad/tracker through (${head}) | Blocked (${head}) | DOMContentLoaded ms (${head}) | Load ms (${head}) | JS heap MB (${head}) |`);
  lines.push(`|---|---|---|---|---|---|---|`);
  const totals: Record<string, { through: number; attempts: number; blocked: number; requests: number; dcl: number[]; load: number[]; heap: number[] }> = {};
  for (const k of kinds) totals[k] = { through: 0, attempts: 0, blocked: 0, requests: 0, dcl: [], load: [], heap: [] };
  for (const site of r.sites) {
    lines.push(
      `| ${site.name} | ${cell(site, (s) => fmt(s.counts.requests))} | ${cell(site, (s) => fmt(s.counts.adTrackerThrough))} | ${cell(site, (s) => fmt(s.counts.blocked))} | ${cell(site, (s) => fmt(s.timings.dcl))} | ${cell(site, (s) => fmt(s.timings.load))} | ${cell(site, (s) => mb(s.heap.jsHeapUsed))} |`,
    );
    for (const k of kinds) {
      const s = site.results[k];
      if (!s?.ok) continue;
      const t = totals[k];
      t.through += s.counts.adTrackerThrough;
      t.attempts += s.counts.adTrackerAttempts;
      t.blocked += s.counts.blocked;
      t.requests += s.counts.requests;
      if (s.timings.dcl) t.dcl.push(s.timings.dcl);
      if (s.timings.load) t.load.push(s.timings.load);
      if (s.heap.jsHeapUsed) t.heap.push(s.heap.jsHeapUsed);
    }
  }
  lines.push(
    `| **Total / median** | ${kinds.map((k) => fmt(totals[k].requests)).join(' / ')} | ${kinds.map((k) => fmt(totals[k].through)).join(' / ')} | ${kinds.map((k) => fmt(totals[k].blocked)).join(' / ')} | ${kinds.map((k) => fmt(median(totals[k].dcl))).join(' / ')} | ${kinds.map((k) => fmt(median(totals[k].load))).join(' / ')} | ${kinds.map((k) => mb(median(totals[k].heap))).join(' / ')} |`,
  );
  lines.push('');
  if (totals.chromium && (totals.bastion || totals.brave)) {
    const base = totals.chromium.through || 1;
    const pct = (k: string) => (totals[k] ? `${(100 * (1 - totals[k].through / base)).toFixed(1)} %` : '–');
    lines.push(`Reduction of ad/tracker requests that got through, relative to plain Chromium: Bastion ${pct('bastion')}, Brave ${pct('brave')}.`);
    lines.push('');
  }
  const visits = r.sites.map((s) => s.results.bastion).filter((s): s is SiteSummary => !!s?.ok);
  const swLoad = visits.map((s) => s.serviceWorkerAtLoad?.usedSize).filter((x): x is number => typeof x === 'number');
  const swEnd = visits.map((s) => s.serviceWorker?.usedSize).filter((x): x is number => typeof x === 'number');
  if (swLoad.length) {
    lines.push(
      `Bastion service worker JS heap right after the load event: median ${mb(median(swLoad))} MB, max ${mb(Math.max(...swLoad))} MB (${swLoad.length} visits). ` +
        `At the end of the visit the SW was already stopped by Chromium (idle) in ${visits.length - swEnd.length} of ${visits.length} visits` +
        (swEnd.length ? `; when still running: median ${mb(median(swEnd))} MB.` : '.'),
    );
  }
  lines.push('');
  // Where one blocker lets through what the other stops: the actionable lists for filter work.
  if (kinds.includes('bastion') && kinds.includes('brave')) {
    for (const [a, b] of [['bastion', 'brave'], ['brave', 'bastion']] as const) {
      lines.push(`### Ad/tracker hosts that got through in ${LABEL[a]} but not in ${LABEL[b]}`);
      lines.push('');
      const diff = new Map<string, number>();
      for (const site of r.sites) {
        const x = site.results[a];
        const y = site.results[b];
        if (!x?.ok || !y?.ok) continue;
        for (const [h, n] of Object.entries(x.throughHosts)) if (!y.throughHosts[h]) diff.set(`${h} (${site.name})`, n);
      }
      const top = [...diff.entries()].sort((p, q) => q[1] - p[1]).slice(0, 30);
      lines.push(top.length ? top.map(([h, n]) => `- ${h}: ${n}`).join('\n') : '- none');
      lines.push('');
    }
  }
  if (r.rea.enabled) {
    lines.push(`### REA cross-check`);
    lines.push('');
    lines.push(`REA ${r.rea.version ?? ''} (\`rea inspect-web-page --observation-ms ${r.options.reaObservationMs ?? 8000}\`) attached to each browser's loopback CDP endpoint after the load event. ${r.rea.note}`);
    lines.push('');
    lines.push(`Columns: ad/tracker entries in REA's resource inventory; how many had content; how many of those our CDP capture identified as neutered stubs (REA sees the stub under the original URL, e.g. a 5 KB gpt.js); entries REA lists without content (blocked or failed requests, also 204 beacons); disagreements = content per REA but hard-blocked per CDP; hosts REA saw that our capture missed.`);
    lines.push('');
    lines.push(`| Site | Browser | REA | Resources | Ad/tracker entries | with content | confirmed stubs | no content | disagreements | missed by CDP |`);
    lines.push(`|---|---|---|---|---|---|---|---|---|---|`);
    for (const site of r.sites) {
      for (const k of kinds) {
        const x = site.rea[k];
        if (!x) continue;
        const c = x.check;
        lines.push(
          `| ${site.name} | ${LABEL[k]} | ${x.ok ? 'ok' : 'failed: ' + (x.error ?? '').slice(0, 80).replace(/\|/g, '/')} | ${fmt(x.resources)} | ${fmt(c?.adTrackerResources)} | ${fmt(c?.adTrackerWithContent)} | ${fmt(c?.confirmedStubs.length)} | ${fmt(c?.emptyResources)} | ${c ? (c.disagreements.length ? c.disagreements.map((d) => d.split(' (')[0]).join('<br>') : '0') : '–'} | ${c ? (c.notInCapture.length ? c.notInCapture.join(', ') : '0') : '–'} |`,
        );
      }
    }
    lines.push('');
  }
  lines.push(`Raw data: \`test/bench/results/${r.startedAt.slice(0, 10)}*.json\`.`);
  lines.push('');
  return lines.join('\n');
}
