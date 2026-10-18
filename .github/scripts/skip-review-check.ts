// Decides whether a release qualifies for the Chrome Web Store's expedited
// ("skip review") path, by comparing the unpacked previous and new packages.
// Rules (https://developer.chrome.com/docs/webstore/skip-review): only files
// referenced by declarative_net_request.rule_resources change, every added,
// changed or removed rule is a safe rule (block, allow, allowAllRequests,
// upgradeScheme), no ruleset is added or removed, nothing else changes; the
// manifest version must be bumped and is ignored for the comparison.
//
// Usage: node .github/scripts/skip-review-check.ts --old <dir> --new <dir>
// Prints the verdict and reasons; writes eligible=true|false to $GITHUB_OUTPUT
// when set. Exit code 0 for a verdict either way, 2 for usage/IO errors.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SAFE_ACTIONS = new Set(['block', 'allow', 'allowAllRequests', 'upgradeScheme']);
// Keys Chromium understands on a rule; anything else (e.g. "_metadata") is
// ignored by the store when it judges eligibility.
const RULE_KEYS = ['id', 'priority', 'action', 'condition'] as const;
const MAX_REASONS = 25;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function listFiles(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(relative(root, p).split(sep).join('/'), createHash('sha256').update(readFileSync(p)).digest('hex'));
    }
  };
  walk(root);
  return out;
}

/** JSON with sorted object keys, so that key order does not count as a change. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

interface RuleResource {
  id: string;
  enabled: boolean;
  path: string;
}

function ruleResources(manifest: Record<string, unknown>): RuleResource[] {
  const dnr = manifest.declarative_net_request as { rule_resources?: RuleResource[] } | undefined;
  return Array.isArray(dnr?.rule_resources) ? dnr.rule_resources : [];
}

function normPath(p: string): string {
  return p.replace(/^\.?\//, '');
}

type Rule = Record<string, unknown> & { id?: unknown; action?: { type?: unknown } };

function loadRules(root: string, path: string): Map<number, string> | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(join(root, path), 'utf8'));
  } catch (e) {
    return `${path}: cannot read ruleset (${(e as Error).message})`;
  }
  if (!Array.isArray(parsed)) return `${path}: ruleset is not a JSON array`;
  const out = new Map<number, string>();
  for (const r of parsed as Rule[]) {
    if (typeof r?.id !== 'number') return `${path}: rule without numeric id`;
    const stripped: Record<string, unknown> = {};
    for (const k of RULE_KEYS) if (k in r) stripped[k] = r[k];
    out.set(r.id, canonical(stripped));
  }
  return out;
}

function actionOf(ruleJson: string): string {
  try {
    const t = (JSON.parse(ruleJson) as Rule).action?.type;
    return typeof t === 'string' ? t : '?';
  } catch {
    return '?';
  }
}

export function checkSkipReview(oldDir: string, newDir: string): { eligible: boolean; reasons: string[]; summary: string } {
  const reasons: string[] = [];
  const add = (r: string): void => {
    if (reasons.length < MAX_REASONS) reasons.push(r);
    else if (reasons.length === MAX_REASONS) reasons.push('... more reasons omitted');
  };
  const oldManifest = JSON.parse(readFileSync(join(oldDir, 'manifest.json'), 'utf8')) as Record<string, unknown>;
  const newManifest = JSON.parse(readFileSync(join(newDir, 'manifest.json'), 'utf8')) as Record<string, unknown>;

  const perms = (m: Record<string, unknown>): unknown[] => (Array.isArray(m.permissions) ? m.permissions : []);
  if (!perms(newManifest).includes('declarativeNetRequest')) add('declarativeNetRequest is not a required permission');
  if (oldManifest.version === newManifest.version) add(`version was not bumped (${String(newManifest.version)})`);
  const strip = (m: Record<string, unknown>): string => {
    const { version: _ignored, ...rest } = m;
    return canonical(rest);
  };
  if (strip(oldManifest) !== strip(newManifest)) add('manifest.json changed beyond the version field');

  const oldRes = ruleResources(oldManifest);
  const newRes = ruleResources(newManifest);
  const oldIds = new Set(oldRes.map((r) => r.id));
  const newIds = new Set(newRes.map((r) => r.id));
  for (const id of newIds) if (!oldIds.has(id)) add(`ruleset added: ${id}`);
  for (const id of oldIds) if (!newIds.has(id)) add(`ruleset removed: ${id}`);
  const rulesetPaths = new Set(newRes.map((r) => normPath(r.path)));

  const oldFiles = listFiles(oldDir);
  const newFiles = listFiles(newDir);
  let changedRulesets = 0;
  let changedRules = 0;
  for (const path of new Set([...oldFiles.keys(), ...newFiles.keys()])) {
    if (path === 'manifest.json') continue;
    const before = oldFiles.get(path);
    const after = newFiles.get(path);
    if (before === after) continue;
    if (!rulesetPaths.has(path)) {
      add(`${before === undefined ? 'added' : after === undefined ? 'removed' : 'changed'}: ${path} (not a rule_resources file)`);
      continue;
    }
    if (before === undefined || after === undefined) continue; // reported as ruleset add/remove above
    const a = loadRules(oldDir, path);
    const b = loadRules(newDir, path);
    if (typeof a === 'string' || typeof b === 'string') {
      add(typeof a === 'string' ? a : (b as string));
      continue;
    }
    let touched = false;
    for (const id of new Set([...a.keys(), ...b.keys()])) {
      const ra = a.get(id);
      const rb = b.get(id);
      if (ra === rb) continue;
      touched = true;
      changedRules++;
      for (const r of [ra, rb]) {
        if (r !== undefined && !SAFE_ACTIONS.has(actionOf(r))) {
          add(`${path}: rule ${id} ${ra === undefined ? 'added' : rb === undefined ? 'removed' : 'changed'} with unsafe action "${actionOf(r)}"`);
          break;
        }
      }
    }
    if (touched) changedRulesets++;
  }
  const eligible = reasons.length === 0;
  const summary = `${changedRules} rule(s) changed in ${changedRulesets} ruleset file(s)`;
  return { eligible, reasons, summary };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const oldDir = arg('--old');
  const newDir = arg('--new');
  if (!oldDir || !newDir) {
    console.error('usage: node .github/scripts/skip-review-check.ts --old <unpacked previous> --new <unpacked new>');
    process.exit(2);
  }
  let result: ReturnType<typeof checkSkipReview>;
  try {
    result = checkSkipReview(oldDir, newDir);
  } catch (e) {
    console.error(`skip-review check failed: ${(e as Error).message}`);
    process.exit(2);
  }
  console.log(`Chrome Web Store skip review: ${result.eligible ? 'ELIGIBLE' : 'not eligible'} (${result.summary})`);
  for (const r of result.reasons) console.log(`  - ${r}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `eligible=${result.eligible}\n`);
}
