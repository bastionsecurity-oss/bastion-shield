// Bastion Shield — popup command line (nerd mode, docs/NERD-MODE.md): the
// command table, fuzzy matching and suggestions, argument parsing, dashboard
// deep links and the "copy report" JSON. DOM-free so it can be unit tested;
// nerd.ts draws the statusline and runs the commands.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { FpVector, LookalikeHit, NerdBlockedHost } from '../../shared/types.ts';

export type CommandId = 'bisect' | 'bisect cancel' | 'why' | 'blame' | 'allow' | 'fp' | 'copy report' | 'lab' | 'nerd off';

interface CommandDef {
  id: CommandId;
  /** What the user types. */
  name: string;
  /** Argument: a URL or host, filter text, or a host. */
  arg?: 'target' | 'filter' | 'host';
  /** i18n key of the one-line description. */
  desc: string;
}

/** Display order of the full list. */
const COMMANDS: readonly CommandDef[] = [
  { id: 'bisect', name: 'bisect', desc: 'nerdCmdBisect' },
  { id: 'bisect cancel', name: 'bisect cancel', desc: 'nerdCmdBisectCancel' },
  { id: 'why', name: 'why', arg: 'target', desc: 'nerdCmdWhy' },
  { id: 'blame', name: 'blame', arg: 'filter', desc: 'nerdCmdBlame' },
  { id: 'allow', name: 'allow', arg: 'host', desc: 'nerdCmdAllow' },
  { id: 'fp', name: 'fp', desc: 'nerdCmdFp' },
  { id: 'copy report', name: 'copy report', desc: 'nerdCmdCopyReport' },
  { id: 'lab', name: 'lab', desc: 'nerdCmdLab' },
  { id: 'nerd off', name: 'nerd off', desc: 'nerdCmdNerdOff' },
];

/** Rows shown under the prompt. */
export const MAX_SUGGESTIONS = 6;

export interface CommandContext {
  /** A bisect is shown on this tab: offer "bisect cancel" instead of "bisect". */
  bisecting: boolean;
  /** Hosts blocked on this page load, most blocked first (completions for why/allow). */
  hosts: readonly { host: string; count: number }[];
  /** Shortcut labels by command id (e.g. the manifest command for bisect). */
  shortcuts?: Partial<Record<CommandId, string>>;
}

export interface Suggestion {
  id: CommandId;
  /** Command name as typed. */
  name: string;
  /** Argument (may be empty). */
  arg: string;
  /** i18n key of the description; `count` fills host rows ("3 blocked"). */
  desc: string;
  count?: number;
  shortcut?: string;
  /** Text Tab puts into the input. */
  complete: string;
  /** Enter runs it; otherwise Enter completes (an argument is missing). */
  ready: boolean;
}

/**
 * Subsequence match of `query` in `target` (case-insensitive). Higher is
 * better; null = no match. Starts, word starts and runs score; gaps cost.
 */
export function fuzzyScore(query: string, target: string): number | null {
  const q = query.toLowerCase();
  const s = target.toLowerCase();
  if (q === '') return 0;
  let score = 0;
  let at = -1;
  let prev = -2;
  for (const ch of q) {
    const i = s.indexOf(ch, at + 1);
    if (i < 0) return null;
    if (i === 0) score += 8;
    else if (/[\s.\-_/]/.test(s[i - 1]!)) score += 5;
    if (i === prev + 1) score += 4;
    score -= Math.min(3, i - at - 1);
    prev = i;
    at = i;
  }
  // Shorter targets win ties ("fp" over "copy report" for "p").
  return score - s.length * 0.01;
}

function visible(ctx: CommandContext): CommandDef[] {
  return COMMANDS.filter((c) => (ctx.bisecting ? c.id !== 'bisect' : c.id !== 'bisect cancel'));
}

function base(c: CommandDef, ctx: CommandContext): Suggestion {
  // "why" without an argument explains the page itself.
  const ready = !c.arg || c.arg === 'target';
  const s: Suggestion = { id: c.id, name: c.name, arg: '', desc: c.desc, complete: c.arg ? `${c.name} ` : c.name, ready };
  const key = ctx.shortcuts?.[c.id];
  if (key) s.shortcut = key;
  return s;
}

/** Host completions for "why"/"allow" once the name and a space are typed. */
function argSuggestions(c: CommandDef, arg: string, ctx: CommandContext): Suggestion[] {
  const a = arg.trim();
  if (c.arg === 'filter') return [{ ...base(c, ctx), arg: a, complete: `${c.name} ${a}`, ready: a !== '' }];
  const hosts = ctx.hosts
    .map((h, i) => ({ h, i, score: fuzzyScore(a, h.host) }))
    .filter((x) => x.score !== null)
    // Equal matches keep the most-blocked-first order (no length tie-break for hosts).
    .sort((x, y) => Math.round(y.score!) - Math.round(x.score!) || x.i - y.i)
    .map(
      (x): Suggestion => ({ id: c.id, name: c.name, arg: x.h.host, desc: 'nerdCmdHostCount', count: x.h.count, complete: `${c.name} ${x.h.host}`, ready: true }),
    );
  const typed: Suggestion[] = a && !hosts.some((s) => s.arg === a) ? [{ ...base(c, ctx), arg: a, complete: `${c.name} ${a}`, ready: true }] : [];
  // The typed text itself comes after the matching hosts and always keeps its row.
  const out = [...hosts.slice(0, MAX_SUGGESTIONS - typed.length), ...typed];
  return out.length ? out.slice(0, MAX_SUGGESTIONS) : [base(c, ctx)];
}

/** Suggestions for the current input, best first, at most MAX_SUGGESTIONS. */
export function suggest(input: string, ctx: CommandContext): Suggestion[] {
  const raw = input.replace(/^\s+/, '');
  const lower = raw.toLowerCase();
  const cmds = visible(ctx);
  // "allow cdn…", "blame ||ads^": the name is complete, complete the argument.
  for (const c of cmds) {
    if (c.arg && lower.startsWith(`${c.name} `)) return argSuggestions(c, raw.slice(c.name.length + 1), ctx);
  }
  if (lower.trim() === '') return cmds.slice(0, MAX_SUGGESTIONS).map((c) => base(c, ctx));
  return cmds
    .map((c, i) => ({ c, i, score: fuzzyScore(lower.trim(), c.name) }))
    .filter((x) => x.score !== null)
    .sort((x, y) => y.score! - x.score! || x.i - y.i)
    .slice(0, MAX_SUGGESTIONS)
    .map((x) => base(x.c, ctx));
}

// ------------------------------------------------------------- arguments --

/** Hostname from "cdn.example", "https://cdn.example/x" or "CDN.Example." (punycode, lower-case); null if none. */
export function hostFrom(raw: string): string | null {
  const s = raw.trim();
  if (!s || /\s/.test(s)) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    return host && !host.startsWith('[') ? host : null;
  } catch {
    return null;
  }
}

/** URL for "why": a full http(s) URL as given, a bare host as https://host/, nothing = the page. */
export function targetUrl(raw: string, pageUrl: string | null): string | null {
  const s = raw.trim();
  if (!s) return pageUrl;
  if (/^https?:\/\//i.test(s)) {
    try {
      return new URL(s).href;
    } catch {
      return null;
    }
  }
  const host = hostFrom(s);
  return host ? `https://${host}/` : null;
}

/** Dashboard deep links (the dashboard reads these hashes). Paths are relative to the extension root. */
export function labPath(kind: 'lab' | 'why' | 'blame', params: { url?: string; site?: string | null; filter?: string } = {}): string {
  if (kind === 'why') {
    const q = new URLSearchParams();
    q.set('url', params.url ?? '');
    if (params.site) q.set('site', params.site);
    return `ui/dashboard.html#lab?${q.toString()}`;
  }
  if (kind === 'blame') return `ui/dashboard.html#lab/blame?${new URLSearchParams({ filter: params.filter ?? '' }).toString()}`;
  return 'ui/dashboard.html#lab';
}

// ---------------------------------------------------------------- report --

export interface ReportInput {
  site: string | null;
  url: string | null;
  at: number;
  counts: Record<string, number>;
  hosts: readonly NerdBlockedHost[];
  fp: Partial<Record<FpVector, number>> | null;
  clipboardBlocked: number;
  lookalike: LookalikeHit | null;
  version: string;
}

/** "copy report": everything the statusline knows about this page, as stable JSON. */
export function buildReport(r: ReportInput): string {
  return JSON.stringify(
    {
      site: r.site,
      url: r.url,
      at: new Date(r.at).toISOString(),
      counts: r.counts,
      blockedHosts: r.hosts.map((h) => ({ host: h.host, count: h.count, rules: h.rules, filters: h.filters, lists: h.lists })),
      fp: r.fp,
      clipboardBlocked: r.clipboardBlocked,
      lookalike: r.lookalike,
      version: r.version,
    },
    null,
    2,
  );
}
