// Bastion Shield — compare our filter compiler with uBO Lite's DNR output.
//
// Compiles the exact list text uBOL compiled (its build cache) with
// src/compiler and diffs the semantics of both rulesets. Rules are exploded
// into "atoms" (one request domain × one initiator domain × one resource type
// × one action detail) so differences in merging, ids and priority numbers do
// not matter; an atom counts as covered when the other side has an atom with
// the same condition and action class, where a parent domain covers a
// subdomain and a typeless rule covers any non-document type.
//
//   node tools/compare-ubo.ts --ubol-out <uBOL build>/out --ubol-cache <uBOL build>/mv3-data/chromium \
//        [--lists easylist,easyprivacy,pgl,deu-0,ublock-filters] [--samples 12] [--json report.json]
//
// --ubol-out / --ubol-cache default to $UBOL_OUT / $UBOL_CACHE. The badfilter
// pre-pass mirrors uBOL: lists earlier in its rulesets.json (--rulesets,
// default <ubol-out>/../build/rulesets.json) cancel filters in later lists.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { collectBadfilters, compileList, isRedirectCopy, regexToUrlFilter, toRe2 } from '../src/compiler/index.ts';
import type { CompiledRule, DnrRule } from '../src/compiler/types.ts';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (!a.startsWith('--')) continue;
  const eq = a.indexOf('=');
  if (eq !== -1) args.set(a.slice(2, eq), a.slice(eq + 1));
  else if (i + 1 < process.argv.length && !process.argv[i + 1].startsWith('--')) args.set(a.slice(2), process.argv[++i]);
  else args.set(a.slice(2), 'true');
}

const ubolOut = args.get('ubol-out') ?? process.env.UBOL_OUT ?? '';
const ubolCache = args.get('ubol-cache') ?? process.env.UBOL_CACHE ?? '';
if (ubolOut === '' || ubolCache === '' || args.has('help')) {
  console.log('usage: node tools/compare-ubo.ts --ubol-out <dir> --ubol-cache <dir> [--lists a,b] [--samples N] [--json file]');
  process.exit(ubolOut === '' || ubolCache === '' ? 2 : 0);
}
const lists = (args.get('lists') ?? 'easylist,easyprivacy,pgl,deu-0,ublock-filters').split(',').filter((s) => s !== '');
const sampleCount = parseInt(args.get('samples') ?? '12', 10);
const rulesetsFile = args.get('rulesets') ?? path.join(ubolOut, '..', 'build', 'rulesets.json');
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

async function loadRedirectResources(): Promise<Map<string, { path: string; requiresTrust: boolean }>> {
  const file = path.join(repoRoot, 'vendor', 'ublock', 'redirect-resources.js');
  const mod = (await import(pathToFileURL(file).href)) as { default: Map<string, { alias?: string | string[]; requiresTrust?: boolean }> };
  const out = new Map<string, { path: string; requiresTrust: boolean }>();
  for (const [name, details] of mod.default) {
    if (name === 'click2load.html') continue;
    // Same paths as uBOL so both sides compare equal.
    const entry = { path: `/web_accessible_resources/${name}`, requiresTrust: details.requiresTrust === true };
    out.set(name, entry);
    const aliases = details.alias === undefined ? [] : Array.isArray(details.alias) ? details.alias : [details.alias];
    for (const a of aliases) out.set(a, entry);
  }
  return out;
}

function readJson(file: string): DnrRule[] {
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, 'utf8')) as DnrRule[];
}

function rulesetOrder(): string[] {
  try {
    const data = JSON.parse(fs.readFileSync(rulesetsFile, 'utf8')) as { id: string }[];
    return data.map((d) => d.id);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Atoms
// ---------------------------------------------------------------------------

interface Atom {
  cls: string;
  url: string;
  cs: boolean;
  party: string;
  req: string;
  init: string;
  type: string;
  methods: string;
  xmethods: string;
  xtypes: string;
  extra: string;
  xreq: string[];
  xinit: string[];
  rule: DnrRule;
  sources?: string[];
  /** For main_frame block atoms: the url in uBOL's strict-block (regex) spelling. */
  altUrl?: string;
}

const restrSeparator = '[^%.0-9a-z_-]';
/** uBOL make-rulesets.js rePatternFromUrlFilter + toStrictBlockRule decoration. */
function strictRegexFromUrlFilter(s0: string): string {
  let s = s0;
  let anchor = 0;
  if (s.startsWith('||')) {
    anchor = 0b100;
    s = s.slice(2);
  } else if (s.startsWith('|')) {
    anchor = 0b010;
    s = s.slice(1);
  }
  if (s.endsWith('|')) {
    anchor |= 0b001;
    s = s.slice(0, -1);
  }
  let re = s
    .replace(/[.+?${}()|[\]\\]/g, '\\$&')
    .replace(/\^/g, restrSeparator)
    .replace(/^\*+|\*+$/g, '')
    .replace(/\*+/g, '.*?');
  if (anchor & 0b100) re = (re.startsWith('\\.') ? '^[^:]+://([^:/]+)?' : '^[^:]+://([^:/]+\\.)?') + re;
  else if (anchor & 0b010) re = '^' + re;
  if (anchor & 0b001) re += '$';
  else if (re.endsWith(restrSeparator)) re += '?';
  return decorateStrict(new RegExp(re).source);
}
function decorateStrict(r0: string): string {
  let r = r0;
  if (!r.startsWith('^')) r = `^.*${r}`;
  if (!r.endsWith('$') && !r.endsWith('.*') && !r.endsWith('.+')) r = `${r}.*`;
  return r;
}

function normUrl(u: string, cs: boolean): string {
  let s = u;
  if (!s.startsWith('|')) s = s.replace(/^\*+/, '');
  if (!s.endsWith('|')) s = s.replace(/\*+$/, '');
  return cs ? s : s.toLowerCase();
}

const reHostOnly = /^\|\|([a-z0-9_-]+(?:\.[a-z0-9_-]+)*)\^$/;

function basename(p: string): string {
  return p.slice(p.lastIndexOf('/') + 1);
}

function atomsOf(rule: DnrRule, side: 'ubol' | 'ours', strictFile: boolean, sources?: string[]): Atom[] {
  const c = rule.condition ?? {};
  const pr = rule.priority ?? 1;
  const act = rule.action;
  let cls = act.type as string;
  let extras: string[] = [''];
  let strict = strictFile;
  switch (act.type) {
    case 'block':
      cls = pr >= 40 ? 'important' : side === 'ubol' && pr >= 21 ? 'block-exredirect' : 'block';
      break;
    case 'allow':
      cls = pr <= 1 ? 'allow-modifier' : 'allow';
      break;
    case 'allowAllRequests':
      cls = 'allowAll';
      break;
    case 'redirect': {
      const r = act.redirect ?? {};
      if (r.extensionPath !== undefined && r.extensionPath.includes('blocked.html')) strict = true;
      else if (r.regexSubstitution !== undefined && r.regexSubstitution.includes('strictblock')) strict = true;
      else if (r.extensionPath !== undefined) cls = `${pr >= 41 ? 'important-redirect' : 'redirect'}:${basename(r.extensionPath)}`;
      else if (r.transform?.query === '') cls = 'removeparam-all';
      else if (r.transform?.queryTransform?.removeParams !== undefined) {
        cls = 'removeparam';
        extras = r.transform.queryTransform.removeParams.slice();
      } else cls = `redirect:${JSON.stringify(r)}`;
      break;
    }
    case 'modifyHeaders':
      cls = 'modifyHeaders';
      extras = (act.responseHeaders ?? []).map((h) => `${h.header.toLowerCase()}|${h.operation}|${h.value ?? ''}`);
      break;
  }
  if (strict) cls = 'strict';
  const cs = c.isUrlFilterCaseSensitive === true;
  let url = '';
  let altUrl = '';
  let reqList = c.requestDomains;
  if (strict) {
    if (side === 'ubol') {
      url = c.regexFilter === undefined || c.regexFilter === '^https?://.*' ? '' : `r:${c.regexFilter}`;
    } else if (c.urlFilter !== undefined) {
      const m = reHostOnly.exec(c.urlFilter);
      if (m !== null && reqList === undefined) reqList = [m[1]];
      else url = `r:${strictRegexFromUrlFilter(c.urlFilter)}`;
    } else if (c.regexFilter !== undefined) {
      url = `r:${decorateStrict(c.regexFilter)}`;
    }
  } else {
    let uf = c.urlFilter;
    if (uf === undefined && c.regexFilter !== undefined) {
      const lit = regexToUrlFilter(c.regexFilter);
      if (lit !== null) uf = lit;
      else url = `r:${toRe2(c.regexFilter) ?? c.regexFilter}`;
      altUrl = `r:${decorateStrict(c.regexFilter)}`;
    }
    if (c.urlFilter !== undefined) altUrl = reHostOnly.test(c.urlFilter) ? '' : `r:${strictRegexFromUrlFilter(c.urlFilter)}`;
    if (uf !== undefined) {
      const n = normUrl(uf, cs);
      const m = reHostOnly.exec(n);
      if (m !== null && reqList === undefined) reqList = [m[1]];
      else if (n !== '') url = `u:${n}`;
    }
  }
  const types = strict ? ['main_frame'] : c.resourceTypes ?? ['*'];
  const reqs = reqList ?? ['*'];
  const inits = c.initiatorDomains ?? ['*'];
  const base = {
    cls,
    url,
    cs: cs && url !== '' && !strict,
    party: c.domainType ?? '',
    methods: (c.requestMethods ?? []).slice().sort().join(','),
    xmethods: (c.excludedRequestMethods ?? []).slice().sort().join(','),
    xtypes: strict ? '' : (c.excludedResourceTypes ?? []).slice().sort().join(','),
    xreq: (c.excludedRequestDomains ?? []).slice().sort(),
    xinit: (c.excludedInitiatorDomains ?? []).slice().sort(),
    rule,
    sources,
  };
  const out: Atom[] = [];
  for (const req of reqs) {
    for (const init of inits) {
      for (const type of types) {
        // Exclusions outside this atom's own domain cannot affect it (uBOL
        // merges exclusion lists across rules, which would otherwise differ).
        const xreq = req === '*' ? base.xreq : base.xreq.filter((x) => x === req || x.endsWith(`.${req}`));
        const xinit = init === '*' ? base.xinit : base.xinit.filter((x) => x === init || x.endsWith(`.${init}`));
        for (const extra of extras) {
          out.push({ ...base, req, init, type, extra, xreq, xinit, altUrl: type === 'main_frame' && !strict ? altUrl : undefined });
        }
      }
    }
  }
  return out;
}

const keyOf = (a: { cls: string; url: string; cs: boolean; party: string; req: string; init: string; type: string; methods: string; xmethods: string; xtypes: string; extra: string }): string =>
  `${a.cls}\u0001${a.url}\u0001${a.cs ? 1 : 0}\u0001${a.party}\u0001${a.req}\u0001${a.init}\u0001${a.type}\u0001${a.methods}\u0001${a.xmethods}\u0001${a.xtypes}\u0001${a.extra}`;

class AtomIndex {
  map = new Map<string, Atom[]>();
  add(a: Atom): void {
    this.put(keyOf(a), a);
    // A document block can stand in for a strict-block rule and vice versa.
    if ((a.cls === 'block' || a.cls === 'important') && a.type === 'main_frame' && a.altUrl !== undefined) {
      this.put(keyOf({ ...a, cls: 'strict', url: a.altUrl, cs: false, xtypes: '' }), a);
    }
  }
  private put(k: string, a: Atom): void {
    const l = this.map.get(k);
    if (l === undefined) this.map.set(k, [a]);
    else l.push(a);
  }
  /** Does this index hold an atom covering `a` (same or broader on domains/types)? */
  covers(a: Atom, ignoreExclusions = false): Atom | null {
    // A parent domain or "any" covers a domain; the reverse comparison
    // (our atoms against uBOL's) catches rules of ours that are too broad.
    const parents = (d: string): string[] => {
      if (d === '*') return ['*'];
      const out = [d];
      let p = d.indexOf('.');
      while (p !== -1) {
        out.push(d.slice(p + 1));
        p = d.indexOf('.', p + 1);
      }
      out.push('*');
      return out;
    };
    const clsCands = [a.cls];
    if ((a.cls === 'block' || a.cls === 'important') && a.type === 'main_frame') clsCands.push('strict');

    // @@…$document: uBOL emits allow main_frame, we emit allowAllRequests (§4.4).
    if (a.cls === 'allow' && (a.type === 'main_frame' || a.type === 'sub_frame')) clsCands.push('allowAll');
    if (a.cls === 'allowAll') clsCands.push('allow');
    const typeCands = a.type === '*' ? ['*'] : a.type === 'main_frame' ? ['main_frame'] : [a.type, '*'];
    for (const cls of clsCands) {
      for (const req of parents(a.req)) {
        for (const init of parents(a.init)) {
          for (const type of typeCands) {
            const toStrict = cls === 'strict' && a.cls !== 'strict';
            const cand = this.map.get(keyOf({
              ...a,
              cls,
              req,
              init,
              type,
              url: toStrict ? a.altUrl ?? a.url : a.url,
              cs: toStrict ? false : a.cs,
              xtypes: cls === 'strict' || a.cls === 'strict' ? '' : a.xtypes,
            }));
            if (cand === undefined) continue;
            for (const b of cand) {
              if (ignoreExclusions) return b;
              if (b.xreq.every((x) => a.xreq.includes(x)) && b.xinit.every((x) => a.xinit.includes(x))) return b;
            }
          }
        }
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

const QUIRK_CRLF = 'uBO quirk: in CRLF lists "||host" (no ^) is parsed as a hostname, in LF lists as a prefix pattern; we always use the LF reading';

function ubolReason(a: Atom, ours: AtomIndex): string {
  const c = a.rule.condition ?? {};
  if (c.resourceTypes !== undefined && c.excludedResourceTypes !== undefined) {
    return 'uBOL bug: rule has both resourceTypes and excludedResourceTypes (Chrome rejects it)';
  }
  if (a.req !== '*' && a.url === '' && ours.covers({ ...a, req: '*', url: `u:||${a.req}`, cls: a.cls === 'strict' ? 'block' : a.cls, type: a.cls === 'strict' ? '*' : a.type, xtypes: '' }, true) !== null) {
    return QUIRK_CRLF;
  }
  if (c.topDomains !== undefined || c.excludedTopDomains !== undefined) return 'uBOL-only: $top= (topDomains needs Chrome 145; rejected by design)';
  if (c.responseHeaders !== undefined || c.excludedResponseHeaders !== undefined) return 'uBOL-only: $header= (rejected by design, ARCHITECTURE §4.4)';
  if (a.cls === 'modifyHeaders' && a.extra.startsWith('permissions-policy')) return 'by design: $permissions keeps initiatorDomains for sub_frame (uBOL moves them to requestDomains)';
  if (a.cls === 'block-exredirect') return 'uBOL-only: @@…$redirect turned into a block rule (rejected by design)';
  if (a.type === 'main_frame' && a.party !== '') return 'by design: $1p/$3p on documents (a document is first-party to itself, uBO semantics)';
  if (a.type === 'main_frame' && (a.init !== '*' || a.xinit.length !== 0)) return 'by design: main_frame $domain= mapped to requestDomains (uBO semantics for documents)';
  if (/^u:.*\$~?[a-z][a-z0-9_-]*(?:=[^,]*)?(?:,|$)/.test(a.url)) return 'by design: an unknown option is reported (uBO makes "$option" part of the pattern)';
  const mq = /^u:\|\|([a-z0-9.-]+)$/.exec(a.url);
  if (mq !== null && a.req === '*' && ours.covers({ ...a, url: '', req: mq[1] }, true) !== null) return QUIRK_CRLF;
  if (a.cls === 'removeparam' && a.type === 'main_frame' && a.req !== '*') {
    return 'uBOL bug: removeparam main_frame rule gets requestDomains ∪ initiatorDomains (expandRemoveparamsRule; should be ∩)';
  }
  if (a.url.startsWith('r:') && toRe2(a.url.slice(2)) === null) return 'uBOL-only: regex RE2 cannot compile (Chrome drops it at runtime)';
  if (a.cls === 'removeparam' && a.extra.startsWith('~')) return 'uBOL bug: negated $removeparam=~x emitted as removeParams ["~x"] (a no-op); we reject it';
  if (a.cls === 'strict') return 'strict-block difference';
  if (c.regexFilter !== undefined && a.cls.startsWith('redirect:{')) return 'uBOL-only: $uritransform (rejected by design)';
  if (a.url.startsWith('r:')) return 'regex difference';
  return 'other';
}

function oursReason(a: Atom, ubol: AtomIndex): string {
  if (ubol.covers(a, true) !== null) return 'uBOL merges exclusion lists of different rules (its rule is narrower than the filters)';
  const m = /^u:\|\|([a-z0-9.-]+)$/.exec(a.url);
  if (m !== null && a.req === '*' && ubol.covers({ ...a, url: '', req: m[1] }, true) !== null) return QUIRK_CRLF;
  const src = pickSource(a) ?? '';
  const opts = src.includes('$') ? src.slice(src.lastIndexOf('$') + 1) : '';
  if (a.type === 'main_frame' && (a.req !== '*' || a.xreq.length !== 0) && (a.sources ?? []).some((x) => /[$,](?:domain|from)=|##\^responseheader\(/.test(x))) {
    return 'by design: main_frame $domain= mapped to requestDomains (uBO semantics for documents)';
  }
  if (/(^|,)match-case(,|$)/.test(opts) && !/^@?@?\//.test(src)) return 'ours-only: $match-case on a non-regex pattern (uBO rejects the filter)';
  if (a.cls === 'allowAll' && a.type === 'sub_frame') return 'by design: @@…$document -> allowAllRequests on main_frame + sub_frame';
  if (a.cls === 'strict') return 'ours-only: strict-block';
  if (a.type === 'main_frame') return 'ours-only: main_frame part';
  if (a.cls === 'modifyHeaders' && /permissions=/.test(opts)) return 'by design: $permissions keeps initiatorDomains for sub_frame (uBOL moves them to requestDomains)';
  return 'other';
}

function pickSource(a: Atom): string | undefined {
  if (a.sources === undefined) return undefined;
  const needle = a.req !== '*' ? a.req : a.init !== '*' ? a.init : a.url.slice(2).replace(/^\|+/, '').slice(0, 30);
  return a.sources.find((s) => s.toLowerCase().includes(needle.toLowerCase())) ?? a.sources[0];
}

function findInput(lines: string[], a: Atom): string | undefined {
  const needles: string[] = [];
  if (a.url.startsWith('u:')) needles.push(a.url.slice(2).replace(/^\|+/, '').replace(/\|$/, '').replace(/\^$/, ''));
  if (a.req !== '*') needles.push(a.req);
  if (a.init !== '*') needles.push(a.init);
  if (a.extra !== '') needles.push(a.extra.split('|')[0]);
  const ns = needles.filter((n) => n.length > 2).map((n) => n.toLowerCase());
  if (ns.length === 0) return undefined;
  for (const l of lines) {
    const ll = l.toLowerCase();
    if (ns.every((n) => ll.includes(n))) return l;
  }
  for (const l of lines) if (l.toLowerCase().includes(ns[0])) return l;
  return undefined;
}

function describe(a: Atom): string {
  const parts = [a.cls];
  if (a.url !== '') parts.push(a.url);
  if (a.req !== '*') parts.push(`req=${a.req}`);
  if (a.init !== '*') parts.push(`init=${a.init}`);
  if (a.type !== '*') parts.push(`type=${a.type}`);
  if (a.party !== '') parts.push(a.party);
  if (a.extra !== '') parts.push(`[${a.extra}]`);
  if (a.xreq.length) parts.push(`xreq=${a.xreq.slice(0, 3).join('|')}${a.xreq.length > 3 ? '…' : ''}`);
  if (a.xinit.length) parts.push(`xinit=${a.xinit.slice(0, 3).join('|')}${a.xinit.length > 3 ? '…' : ''}`);
  if (a.xtypes !== '') parts.push(`xtypes=${a.xtypes}`);
  if (a.methods !== '') parts.push(`methods=${a.methods}`);
  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface ListReport {
  id: string;
  ubolRules: { main: number; regex: number; strict: number };
  ourRules: { main: number; regex: number; strictBlockRules: number };
  ubolAtoms: number;
  covered: number;
  coveredIgnoringExclusions: number;
  coverage: number;
  ourAtoms: number;
  oursCovered: number;
  onlyInUbol: Record<string, { count: number; samples: string[] }>;
  onlyInOurs: Record<string, { count: number; samples: string[] }>;
  compileMs: number;
  unsupported: Record<string, number>;
  /** uBOL atoms we miss for a documented reason (by design, uBOL bug, uBO quirk). */
  explained: number;
  unexplained: number;
}

/** Reasons that are intentional differences or defects on the uBOL side. */
const isExplained = (reason: string): boolean => /^(?:by design|uBOL-only|uBOL bug|uBO quirk|uBOL merges)/.test(reason);

async function main(): Promise<void> {
  const redirectResources = await loadRedirectResources();
  const order = rulesetOrder();
  const reports: ListReport[] = [];
  for (const id of lists) {
    const inputFile = path.join(ubolCache, id);
    if (!fs.existsSync(inputFile)) {
      console.error(`skip ${id}: no cached input at ${inputFile}`);
      continue;
    }
    const text = fs.readFileSync(inputFile, 'utf8');
    const before = order.indexOf(id) === -1 ? [] : order.slice(0, order.indexOf(id));
    const badTexts = [...before.map((b) => path.join(ubolCache, b)).filter((f) => fs.existsSync(f)).map((f) => fs.readFileSync(f, 'utf8')), text];
    const badfilters = collectBadfilters(badTexts);
    const t0 = performance.now();
    const compiled = compileList(text, {
      listId: id,
      trusted: id.startsWith('ublock-'),
      firstPartyProtected: true,
      strictBlock: true,
      redirectResources,
      scriptlets: new Map(),
      badfilters,
      maxRejectedSamples: 0,
    });
    const compileMs = Math.round(performance.now() - t0);

    const ubolMain = readJson(path.join(ubolOut, 'rulesets', 'main', `${id}.json`));
    const ubolRegex = readJson(path.join(ubolOut, 'rulesets', 'regex', `${id}.json`));
    const ubolStrict = readJson(path.join(ubolOut, 'rulesets', 'strictblock', `${id}.json`));
    const ubolIdx = new AtomIndex();
    const ubolAtoms: Atom[] = [];
    for (const r of [...ubolMain, ...ubolRegex]) for (const a of atomsOf(r, 'ubol', false)) ubolAtoms.push(a);
    for (const r of ubolStrict) for (const a of atomsOf(r, 'ubol', true)) ubolAtoms.push(a);
    for (const a of ubolAtoms) ubolIdx.add(a);

    const ourIdx = new AtomIndex();
    const ourAtoms: Atom[] = [];
    // Third-party copies of protected-list redirects (BS-1) duplicate a rule that stays;
    // the build prunes most of them (restrictRedirectCopies), so they are not compared.
    const all: CompiledRule[] = [...compiled.rules, ...compiled.regexRules].filter((cr) => !isRedirectCopy(cr.rule));
    for (const cr of all) for (const a of atomsOf(cr.rule, 'ours', false, cr.sources)) ourAtoms.push(a);
    for (const a of ourAtoms) ourIdx.add(a);

    const inputLines = text.split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('!') && !/#@?[$%?]?\??#/.test(l));
    const onlyUbol = new Map<string, Atom[]>();
    let covered = 0;
    let coveredLoose = 0;
    for (const a of ubolAtoms) {
      if (ourIdx.covers(a) !== null) {
        covered += 1;
        coveredLoose += 1;
        continue;
      }
      if (ourIdx.covers(a, true) !== null) coveredLoose += 1;
      const reason = ubolReason(a, ourIdx);
      const l = onlyUbol.get(reason);
      if (l === undefined) onlyUbol.set(reason, [a]);
      else l.push(a);
    }
    const onlyOurs = new Map<string, Atom[]>();
    let oursCovered = 0;
    for (const a of ourAtoms) {
      if (ubolIdx.covers(a) !== null) {
        oursCovered += 1;
        continue;
      }
      const reason = oursReason(a, ubolIdx);
      const l = onlyOurs.get(reason);
      if (l === undefined) onlyOurs.set(reason, [a]);
      else l.push(a);
    }
    const group = (m: Map<string, Atom[]>, side: 'ubol' | 'ours'): Record<string, { count: number; samples: string[] }> => {
      const out: Record<string, { count: number; samples: string[] }> = {};
      for (const [reason, atoms] of [...m].sort((x, y) => y[1].length - x[1].length)) {
        const samples: string[] = [];
        const seen = new Set<string>();
        for (const a of atoms) {
          if (samples.length >= sampleCount) break;
          const src = side === 'ours' ? pickSource(a) : findInput(inputLines, a);
          const line = `${describe(a)}${src !== undefined ? `   <=  ${src.length > 160 ? src.slice(0, 160) + '…' : src}` : ''}`;
          if (seen.has(src ?? line)) continue;
          seen.add(src ?? line);
          samples.push(line);
        }
        out[reason] = { count: atoms.length, samples };
      }
      return out;
    };
    const unsupported: Record<string, number> = {};
    for (const [k, v] of Object.entries(compiled.stats.reasons)) if (!k.startsWith('warn:')) unsupported[k] = v;
    reports.push({
      id,
      ubolRules: { main: ubolMain.length, regex: ubolRegex.length, strict: ubolStrict.length },
      ourRules: {
        main: compiled.rules.length,
        regex: compiled.regexRules.length,
        strictBlockRules: all.filter((r) => r.rule.priority === 29).length,
      },
      ubolAtoms: ubolAtoms.length,
      covered,
      coveredIgnoringExclusions: coveredLoose,
      coverage: ubolAtoms.length === 0 ? 100 : (100 * covered) / ubolAtoms.length,
      ourAtoms: ourAtoms.length,
      oursCovered,
      onlyInUbol: group(onlyUbol, 'ubol'),
      onlyInOurs: group(onlyOurs, 'ours'),
      compileMs,
      unsupported,
      explained: [...onlyUbol].filter(([k]) => isExplained(k)).reduce((n, [, v]) => n + v.length, 0),
      unexplained: [...onlyUbol].filter(([k]) => !isExplained(k)).reduce((n, [, v]) => n + v.length, 0),
    });
  }

  for (const r of reports) {
    console.log(`\n=== ${r.id}  (compiled in ${r.compileMs} ms)`);
    console.log(`uBOL rules: ${r.ubolRules.main} main + ${r.ubolRules.regex} regex + ${r.ubolRules.strict} strict-block`);
    console.log(`our rules:  ${r.ourRules.main} plain + ${r.ourRules.regex} regex (of which ${r.ourRules.strictBlockRules} strict-block)`);
    console.log(`coverage of uBOL semantics: ${r.coverage.toFixed(2)}% (${r.covered}/${r.ubolAtoms} atoms; ${((100 * r.coveredIgnoringExclusions) / Math.max(1, r.ubolAtoms)).toFixed(2)}% ignoring exclusion lists)`);
    console.log(`uBOL atoms we miss: ${r.explained} explained (by design / uBOL bug / uBO quirk), ${r.unexplained} unexplained`);
    console.log(`our atoms covered by uBOL: ${((100 * r.oursCovered) / Math.max(1, r.ourAtoms)).toFixed(2)}% (${r.oursCovered}/${r.ourAtoms})`);
    for (const [title, groups] of [['only in uBOL', r.onlyInUbol], ['only in ours', r.onlyInOurs]] as const) {
      for (const [reason, g] of Object.entries(groups)) {
        console.log(`  [${title}] ${reason}: ${g.count}`);
        for (const s of g.samples) console.log(`      ${s}`);
      }
    }
  }
  console.log('\nsummary:');
  for (const r of reports) {
    const adj = (100 * (r.covered + r.explained)) / Math.max(1, r.ubolAtoms);
    console.log(`  ${r.id.padEnd(22)} coverage ${r.coverage.toFixed(2).padStart(6)}% (${adj.toFixed(2)}% incl. explained)   uBOL ${String(r.ubolRules.main + r.ubolRules.regex).padStart(6)} rules   ours ${String(r.ourRules.main + r.ourRules.regex).padStart(6)} rules   ${r.compileMs} ms`);
  }
  const jsonOut = args.get('json');
  if (jsonOut !== undefined) fs.writeFileSync(jsonOut, JSON.stringify(reports, null, 2));
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
