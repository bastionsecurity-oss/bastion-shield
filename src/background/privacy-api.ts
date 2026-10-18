// Bastion Shield service worker — browser privacy levers (ARCHITECTURE §9):
// chrome.privacy settings and per-site JavaScript blocking through
// chrome.contentSettings. We only touch a setting while we may control it
// (levelOfControl) and release control when the feature is switched off, so
// enterprise policy and other extensions always win and nothing is fought over.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Settings, SitesMap } from '../shared/types.ts';
import * as log from './log.ts';
import { explicitField, sitePattern } from './sites.ts';
import { hostnameCandidates } from '../shared/hash.ts';
import { canonicalJson } from './util.ts';

export interface PrivacyTarget {
  /** e.g. "websites.hyperlinkAuditingEnabled" */
  key: string;
  /** null = release our control (clear). */
  value: boolean | string | null;
}

/**
 * What we want for every chrome.privacy lever. `releaseAll` (fleet kill
 * switch) releases every setting this extension controls.
 */
export function desiredPrivacy(settings: Settings, releaseAll = false): PrivacyTarget[] {
  const p = settings.privacy;
  const sandbox = p.disablePrivacySandboxAds ? false : null;
  const targets: PrivacyTarget[] = [
    { key: 'websites.hyperlinkAuditingEnabled', value: p.blockHyperlinkAuditing ? false : null },
    { key: 'websites.topicsEnabled', value: sandbox },
    { key: 'websites.fledgeEnabled', value: sandbox },
    { key: 'websites.adMeasurementEnabled', value: sandbox },
    { key: 'network.webRTCIPHandlingPolicy', value: p.webrtcPolicy === 'default' ? null : p.webrtcPolicy },
    // false means "do not block via Bastion": leave the browser's own choice alone.
    { key: 'websites.thirdPartyCookiesAllowed', value: p.blockThirdPartyCookies === true ? false : null },
  ];
  return releaseAll ? targets.map((t) => ({ key: t.key, value: null })) : targets;
}

type Level = 'not_controllable' | 'controlled_by_other_extensions' | 'controllable_by_this_extension' | 'controlled_by_this_extension';

/** What to do with one setting given its current state. */
export function privacyAction(target: PrivacyTarget, current: { value: unknown; levelOfControl: Level }): 'set' | 'clear' | 'none' {
  const ours = current.levelOfControl === 'controlled_by_this_extension';
  if (target.value === null) return ours ? 'clear' : 'none';
  if (current.levelOfControl !== 'controllable_by_this_extension' && !ours) return 'none';
  if (ours && current.value === target.value) return 'none';
  return 'set';
}

interface ChromeSetting {
  get(details: object): Promise<{ value: unknown; levelOfControl: Level }>;
  set(details: { value: unknown }): Promise<void>;
  clear(details: object): Promise<void>;
}

function settingFor(key: string): ChromeSetting | null {
  try {
    const [ns, name] = key.split('.');
    const group = (chrome.privacy as unknown as Record<string, Record<string, ChromeSetting | undefined> | undefined>)[ns];
    const s = group?.[name];
    return s && typeof s.get === 'function' ? s : null;
  } catch {
    return null;
  }
}

export async function applyPrivacySettings(settings: Settings, releaseAll = false): Promise<string[]> {
  const problems: string[] = [];
  if (typeof chrome.privacy !== 'object' || chrome.privacy === null) return problems;
  await Promise.all(
    desiredPrivacy(settings, releaseAll).map(async (t) => {
      const s = settingFor(t.key);
      if (!s) return; // not available in this browser (e.g. Privacy Sandbox APIs on Brave)
      try {
        const cur = await s.get({});
        const action = privacyAction(t, cur);
        if (action === 'set') await s.set({ value: t.value });
        else if (action === 'clear') await s.clear({});
      } catch (e) {
        problems.push(`${t.key}: ${String(e)}`);
        log.warn('privacy', t.key, e);
      }
    }),
  );
  return problems;
}

export interface ScriptSetting {
  pattern: string;
  setting: 'block' | 'allow';
}

/**
 * Per-site "block scripts": block where set; an explicit `false` below a
 * blocked parent becomes "allow" (the more specific pattern wins).
 */
export function desiredScriptSettings(sites: SitesMap): ScriptSetting[] {
  const explicit = explicitField(sites, 'blockScripts');
  const out: ScriptSetting[] = [];
  for (const [site, block] of Array.from(explicit.entries()).sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (block) {
      out.push({ pattern: sitePattern(site), setting: 'block' });
      continue;
    }
    const parentBlocked = hostnameCandidates(site)
      .slice(1)
      .some((p) => explicit.get(p) === true);
    if (parentBlocked) out.push({ pattern: sitePattern(site), setting: 'allow' });
  }
  return out;
}

const SESSION_KEY = 'applied:contentSettings';

/** Idempotent: rewrites our content settings only when the desired set changed. */
export async function applyScriptSettings(sites: SitesMap): Promise<void> {
  const js = chrome.contentSettings?.javascript;
  if (!js) return;
  const desired = desiredScriptSettings(sites);
  const fingerprint = canonicalJson(desired);
  const prev = await log.attempt('contentSettings', () => chrome.storage.session.get(SESSION_KEY), {} as Record<string, unknown>);
  if (prev[SESSION_KEY] === fingerprint) return;
  try {
    await js.clear({ scope: 'regular' });
    for (const d of desired) {
      await js.set({ primaryPattern: d.pattern, setting: d.setting, scope: 'regular' }).catch((e: unknown) => log.warn('contentSettings', d.pattern, e));
    }
    await chrome.storage.session.set({ [SESSION_KEY]: fingerprint });
  } catch (e) {
    log.warn('contentSettings', e);
  }
}
