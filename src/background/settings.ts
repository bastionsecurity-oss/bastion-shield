// Bastion Shield service worker — settings model (ARCHITECTURE §10): defaults,
// tolerant validation of stored/imported data, the managed-policy overlay and
// the list of locked setting paths the UI shows lock icons for. Pure: storage
// I/O lives in store.ts so this module can be tested under Node.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  BlockingMode,
  DeepPartial,
  EffectiveConfig,
  FingerprintLevel,
  ManagedPolicy,
  Settings,
  WebRtcPolicy,
} from '../shared/types.ts';
import { normalizeSiteKey } from './sites.ts';
import { isPlainObject } from './util.ts';

/** What the settings layer needs to know about a filter list. */
export interface ListInfo {
  id: string;
  default: boolean;
  /** Catalog "locked" (hidden, always on unless the policy says otherwise). */
  locked?: boolean;
}

const MODES: readonly BlockingMode[] = ['standard', 'aggressive'];
const FP_LEVELS: readonly FingerprintLevel[] = ['off', 'standard', 'strict'];
const WEBRTC: readonly WebRtcPolicy[] = ['default', 'default_public_interface_only', 'disable_non_proxied_udp'];
const LIST_ID_RE = /^[a-z0-9][a-z0-9.-]{0,63}$/;
export const MAX_RETENTION_DAYS = 3650;

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
    },
    ui: { badge: true, activityLog: true },
    history: { enabled: true, retentionDays: 30 },
  };
}

function bool(v: unknown, fallback: boolean): boolean {
  return typeof v === 'boolean' ? v : fallback;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], fallback: T): T {
  return typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : fallback;
}

function retention(v: unknown, fallback: number): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) return fallback;
  return Math.max(0, Math.min(MAX_RETENTION_DAYS, Math.floor(v)));
}

function listMap(v: unknown): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  if (!isPlainObject(v)) return out;
  for (const [k, val] of Object.entries(v)) {
    if (LIST_ID_RE.test(k) && typeof val === 'boolean') out[k] = val;
  }
  return out;
}

/** Validate stored or imported settings; anything malformed falls back to the default. */
export function normalizeSettings(raw: unknown): Settings {
  const d = defaultSettings();
  if (!isPlainObject(raw)) return d;
  const p = isPlainObject(raw.privacy) ? raw.privacy : {};
  const ui = isPlainObject(raw.ui) ? raw.ui : {};
  const h = isPlainObject(raw.history) ? raw.history : {};
  const cookies = p.blockThirdPartyCookies;
  return {
    version: 1,
    defaultMode: oneOf(raw.defaultMode, MODES, d.defaultMode),
    lists: listMap(raw.lists),
    privacy: {
      gpc: bool(p.gpc, d.privacy.gpc),
      stripParams: bool(p.stripParams, d.privacy.stripParams),
      debounce: bool(p.debounce, d.privacy.debounce),
      deAmp: bool(p.deAmp, d.privacy.deAmp),
      fingerprinting: oneOf(p.fingerprinting, FP_LEVELS, d.privacy.fingerprinting),
      blockHyperlinkAuditing: bool(p.blockHyperlinkAuditing, d.privacy.blockHyperlinkAuditing),
      webrtcPolicy: oneOf(p.webrtcPolicy, WEBRTC, d.privacy.webrtcPolicy),
      blockThirdPartyCookies: typeof cookies === 'boolean' ? cookies : null,
      disablePrivacySandboxAds: bool(p.disablePrivacySandboxAds, d.privacy.disablePrivacySandboxAds),
    },
    ui: {
      badge: bool(ui.badge, d.ui.badge),
      activityLog: bool(ui.activityLog, d.ui.activityLog),
    },
    history: {
      enabled: bool(h.enabled, d.history.enabled),
      retentionDays: retention(h.retentionDays, d.history.retentionDays),
    },
  };
}

// ---------------------------------------------------------------------------
// Managed policy
// ---------------------------------------------------------------------------

/** Policy booleans may arrive as 0/1 (registry DWORD) or strings; accept them. */
function policyBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (v === 0 || v === 1) return v === 1;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    if (s === 'true' || s === '1') return true;
    if (s === 'false' || s === '0') return false;
  }
  return undefined;
}

/** Arrays of strings, a JSON array string, or a comma/newline separated string. */
function policyStrings(v: unknown, max = 50_000): string[] | undefined {
  let arr: unknown = v;
  if (typeof v === 'string') {
    const s = v.trim();
    if (s.startsWith('[')) {
      try {
        arr = JSON.parse(s);
      } catch {
        arr = s.split(/[\n,]+/);
      }
    } else {
      arr = s.split(/[\n,]+/);
    }
  }
  if (!Array.isArray(arr)) return undefined;
  const out: string[] = [];
  for (const x of arr) {
    if (typeof x !== 'string') continue;
    const t = x.trim();
    if (t !== '') out.push(t);
    if (out.length >= max) break;
  }
  return out;
}

function policyString(v: unknown, maxLen = 200): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s === '' ? undefined : s.slice(0, maxLen);
}

function policyUrl(v: unknown): string | undefined {
  const s = policyString(v, 2000);
  if (!s) return undefined;
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Policy host lists: every entry normalised to a site key (lower-case,
 * punycode, leading "www." removed). Invalid entries are dropped one by one,
 * so a single typo does not void the whole list. Duplicates are removed.
 */
function policySites(v: unknown): string[] | undefined {
  const raw = policyStrings(v);
  if (!raw) return undefined;
  const out: string[] = [];
  const seen = new Set<string>();
  for (const h of raw) {
    const k = normalizeSiteKey(h);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

function policyEmail(v: unknown): string | undefined {
  const s = policyString(v, 254);
  return s && /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(s) ? s : undefined;
}

/**
 * Validate the raw chrome.storage.managed object. Unknown keys and invalid
 * values are dropped (Chrome already drops values that violate the schema,
 * but registry/plist edits are a common source of surprises).
 */
export function sanitizeManaged(raw: unknown): ManagedPolicy {
  const out: ManagedPolicy = {};
  if (!isPlainObject(raw)) return out;
  const str = (k: 'organizationName') => {
    const v = policyString(raw[k]);
    if (v !== undefined) out[k] = v;
  };
  str('organizationName');
  const supportUrl = policyUrl(raw.supportUrl);
  if (supportUrl) out.supportUrl = supportUrl;
  const supportEmail = policyEmail(raw.supportEmail);
  if (supportEmail) out.supportEmail = supportEmail;
  if (typeof raw.defaultMode === 'string' && (MODES as readonly string[]).includes(raw.defaultMode)) out.defaultMode = raw.defaultMode as BlockingMode;

  let lists: unknown = raw.lists;
  if (typeof lists === 'string') {
    try {
      lists = JSON.parse(lists);
    } catch {
      lists = undefined;
    }
  }
  if (isPlainObject(lists)) {
    const m: Record<string, boolean> = {};
    for (const [k, v] of Object.entries(lists)) {
      const b = policyBool(v);
      if (LIST_ID_RE.test(k) && b !== undefined) m[k] = b;
    }
    out.lists = m;
  }

  const disabledSites = policySites(raw.disabledSites);
  if (disabledSites) out.disabledSites = disabledSites;
  const aggressiveSites = policySites(raw.aggressiveSites);
  if (aggressiveSites) out.aggressiveSites = aggressiveSites;

  let custom: string[] | undefined;
  if (typeof raw.customFilters === 'string') custom = raw.customFilters.split(/\r?\n/);
  else if (Array.isArray(raw.customFilters)) custom = raw.customFilters.filter((x): x is string => typeof x === 'string');
  if (custom) out.customFilters = custom.flatMap((s) => s.split(/\r?\n/)).map((s) => s.trim()).filter((s) => s !== '').slice(0, 30_000);

  const bools = [
    'lockLists',
    'allowUserSiteToggle',
    'allowUserFilters',
    'lockSettings',
    'gpc',
    'stripParams',
    'debounce',
    'deAmp',
    'blockHyperlinkAuditing',
    'blockThirdPartyCookies',
    'disablePrivacySandboxAds',
    'showBadge',
    'activityLog',
    'historyEnabled',
    'protectionEnabled',
  ] as const;
  for (const k of bools) {
    const b = policyBool(raw[k]);
    if (b !== undefined) out[k] = b;
  }
  if (typeof raw.fingerprinting === 'string' && (FP_LEVELS as readonly string[]).includes(raw.fingerprinting)) {
    out.fingerprinting = raw.fingerprinting as FingerprintLevel;
  }
  if (typeof raw.webrtcPolicy === 'string' && (WEBRTC as readonly string[]).includes(raw.webrtcPolicy)) {
    out.webrtcPolicy = raw.webrtcPolicy as WebRtcPolicy;
  }
  // Registry strings: "" must not become 0 (= keep no history). Clamped to 0..3650.
  const rawDays = raw.historyRetentionDays;
  const days = typeof rawDays === 'string' ? (rawDays.trim() === '' ? Number.NaN : Number(rawDays)) : rawDays;
  if (typeof days === 'number' && Number.isFinite(days)) out.historyRetentionDays = retention(days, 30);
  if (raw.reportBrokenSite === 'github' || raw.reportBrokenSite === 'email' || raw.reportBrokenSite === 'none') {
    out.reportBrokenSite = raw.reportBrokenSite;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Effective config and locks
// ---------------------------------------------------------------------------

/** Every leaf setting path except lists (lockSettings locks all of them). */
export const SETTING_PATHS = [
  'defaultMode',
  'privacy.gpc',
  'privacy.stripParams',
  'privacy.debounce',
  'privacy.deAmp',
  'privacy.fingerprinting',
  'privacy.blockHyperlinkAuditing',
  'privacy.webrtcPolicy',
  'privacy.blockThirdPartyCookies',
  'privacy.disablePrivacySandboxAds',
  'ui.badge',
  'ui.activityLog',
  'history.enabled',
  'history.retentionDays',
] as const;

/** Lock pseudo-paths for things outside Settings (documented for the UI). */
export const LOCK_SITE_TOGGLE = 'sites.enabled';
export const LOCK_CUSTOM_FILTERS = 'customFilters';
export const LOCK_ALL_LISTS = 'lists';

/** Policy key -> setting path it forces. */
const POLICY_PATHS: [keyof ManagedPolicy, (typeof SETTING_PATHS)[number]][] = [
  ['defaultMode', 'defaultMode'],
  ['gpc', 'privacy.gpc'],
  ['stripParams', 'privacy.stripParams'],
  ['debounce', 'privacy.debounce'],
  ['deAmp', 'privacy.deAmp'],
  ['fingerprinting', 'privacy.fingerprinting'],
  ['blockHyperlinkAuditing', 'privacy.blockHyperlinkAuditing'],
  ['webrtcPolicy', 'privacy.webrtcPolicy'],
  ['blockThirdPartyCookies', 'privacy.blockThirdPartyCookies'],
  ['disablePrivacySandboxAds', 'privacy.disablePrivacySandboxAds'],
  ['showBadge', 'ui.badge'],
  ['activityLog', 'ui.activityLog'],
  ['historyEnabled', 'history.enabled'],
  ['historyRetentionDays', 'history.retentionDays'],
];

/**
 * Every list is locked: `lockLists`, or `lockSettings` unless the policy
 * explicitly leaves the lists editable with `lockLists: false`.
 */
export function listsFullyLocked(m: ManagedPolicy): boolean {
  return m.lockLists === true || (m.lockSettings === true && m.lockLists !== false);
}

/**
 * The user's own filters are read-only: `allowUserFilters: false`, or
 * `lockSettings` unless the policy explicitly sets `allowUserFilters: true`.
 */
export function customFiltersLocked(m: ManagedPolicy): boolean {
  return m.allowUserFilters === false || (m.lockSettings === true && m.allowUserFilters !== true);
}

/**
 * Locked setting paths. `lockSettings` locks every dashboard setting, every
 * filter list and the user's own filters (an explicit `lockLists: false` or
 * `allowUserFilters: true` keeps those editable). Per-site mode, scripts and
 * fingerprinting are enforced by the message handlers.
 */
export function lockedPaths(managed: ManagedPolicy, lists: readonly ListInfo[]): string[] {
  const out = new Set<string>();
  if (managed.lockSettings === true) for (const p of SETTING_PATHS) out.add(p);
  for (const [key, path] of POLICY_PATHS) if (managed[key] !== undefined) out.add(path);
  if (listsFullyLocked(managed)) {
    out.add(LOCK_ALL_LISTS);
    for (const l of lists) out.add(`lists.${l.id}`);
  }
  for (const id of Object.keys(managed.lists ?? {})) out.add(`lists.${id}`);
  for (const l of lists) if (l.locked) out.add(`lists.${l.id}`);
  if (managed.allowUserSiteToggle === false) out.add(LOCK_SITE_TOGGLE);
  if (customFiltersLocked(managed)) out.add(LOCK_CUSTOM_FILTERS);
  return Array.from(out).sort();
}

/** Effective enabled state of every known list. */
export function effectiveLists(lists: readonly ListInfo[], user: Settings, managed: ManagedPolicy): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const l of lists) {
    const forced = managed.lists?.[l.id];
    if (forced !== undefined) out[l.id] = forced;
    else if (l.locked) out[l.id] = true;
    else if (listsFullyLocked(managed)) out[l.id] = l.default;
    else out[l.id] = user.lists[l.id] ?? l.default;
  }
  return out;
}

/** User settings with the policy overlaid; `lists` is filled for every known list. */
export function effectiveSettings(user: Settings, managed: ManagedPolicy, lists: readonly ListInfo[]): Settings {
  const s = normalizeSettings(user);
  if (managed.defaultMode !== undefined) s.defaultMode = managed.defaultMode;
  const p = s.privacy;
  if (managed.gpc !== undefined) p.gpc = managed.gpc;
  if (managed.stripParams !== undefined) p.stripParams = managed.stripParams;
  if (managed.debounce !== undefined) p.debounce = managed.debounce;
  if (managed.deAmp !== undefined) p.deAmp = managed.deAmp;
  if (managed.fingerprinting !== undefined) p.fingerprinting = managed.fingerprinting;
  if (managed.blockHyperlinkAuditing !== undefined) p.blockHyperlinkAuditing = managed.blockHyperlinkAuditing;
  if (managed.webrtcPolicy !== undefined) p.webrtcPolicy = managed.webrtcPolicy;
  if (managed.blockThirdPartyCookies !== undefined) p.blockThirdPartyCookies = managed.blockThirdPartyCookies;
  if (managed.disablePrivacySandboxAds !== undefined) p.disablePrivacySandboxAds = managed.disablePrivacySandboxAds;
  if (managed.showBadge !== undefined) s.ui.badge = managed.showBadge;
  if (managed.activityLog !== undefined) s.ui.activityLog = managed.activityLog;
  if (managed.historyEnabled !== undefined) s.history.enabled = managed.historyEnabled;
  if (managed.historyRetentionDays !== undefined) s.history.retentionDays = retention(managed.historyRetentionDays, s.history.retentionDays);
  s.lists = effectiveLists(lists, user, managed);
  return s;
}

export function buildEffectiveConfig(user: Settings, managed: ManagedPolicy, lists: readonly ListInfo[]): EffectiveConfig {
  return {
    settings: effectiveSettings(user, managed, lists),
    managed,
    locked: lockedPaths(managed, lists),
  };
}

/**
 * Merge a settings patch from the UI into the user's settings, skipping
 * locked paths and invalid values. Returns the new settings and the paths
 * that were ignored (so the UI can tell the user why nothing changed).
 */
export function applySettingsPatch(
  user: Settings,
  patch: DeepPartial<Settings> | unknown,
  locked: ReadonlySet<string>,
): { settings: Settings; ignored: string[] } {
  const next = normalizeSettings(user);
  const ignored: string[] = [];
  if (!isPlainObject(patch)) return { settings: next, ignored };

  const set = (path: string, ok: boolean, apply: () => void): void => {
    if (locked.has(path) || !ok) {
      ignored.push(path);
      return;
    }
    apply();
  };

  if ('defaultMode' in patch) {
    const v = patch.defaultMode;
    set('defaultMode', typeof v === 'string' && (MODES as readonly string[]).includes(v), () => (next.defaultMode = v as BlockingMode));
  }
  if (isPlainObject(patch.lists)) {
    for (const [id, v] of Object.entries(patch.lists)) {
      const path = `lists.${id}`;
      set(path, LIST_ID_RE.test(id) && typeof v === 'boolean' && !locked.has(LOCK_ALL_LISTS), () => (next.lists[id] = v as boolean));
    }
  }
  if (isPlainObject(patch.privacy)) {
    const pp = patch.privacy;
    const p = next.privacy;
    const boolKeys = ['gpc', 'stripParams', 'debounce', 'deAmp', 'blockHyperlinkAuditing', 'disablePrivacySandboxAds'] as const;
    for (const k of boolKeys) {
      if (k in pp) set(`privacy.${k}`, typeof pp[k] === 'boolean', () => (p[k] = pp[k] as boolean));
    }
    if ('fingerprinting' in pp) {
      const v = pp.fingerprinting;
      set('privacy.fingerprinting', typeof v === 'string' && (FP_LEVELS as readonly string[]).includes(v), () => (p.fingerprinting = v as FingerprintLevel));
    }
    if ('webrtcPolicy' in pp) {
      const v = pp.webrtcPolicy;
      set('privacy.webrtcPolicy', typeof v === 'string' && (WEBRTC as readonly string[]).includes(v), () => (p.webrtcPolicy = v as WebRtcPolicy));
    }
    if ('blockThirdPartyCookies' in pp) {
      const v = pp.blockThirdPartyCookies;
      set('privacy.blockThirdPartyCookies', typeof v === 'boolean' || v === null, () => (p.blockThirdPartyCookies = v as boolean | null));
    }
  }
  if (isPlainObject(patch.ui)) {
    const u = patch.ui;
    for (const k of ['badge', 'activityLog'] as const) {
      if (k in u) set(`ui.${k}`, typeof u[k] === 'boolean', () => (next.ui[k] = u[k] as boolean));
    }
  }
  if (isPlainObject(patch.history)) {
    const h = patch.history;
    if ('enabled' in h) set('history.enabled', typeof h.enabled === 'boolean', () => (next.history.enabled = h.enabled as boolean));
    if ('retentionDays' in h) {
      const v = h.retentionDays;
      set('history.retentionDays', typeof v === 'number' && Number.isFinite(v), () => (next.history.retentionDays = retention(v, next.history.retentionDays)));
    }
  }
  return { settings: next, ignored };
}

/** Drop list entries that are no longer in the catalog (keeps stored data tidy). */
export function pruneUnknownLists(user: Settings, lists: readonly ListInfo[]): Settings {
  if (lists.length === 0) return user;
  const known = new Set(lists.map((l) => l.id));
  const next = normalizeSettings(user);
  for (const id of Object.keys(next.lists)) if (!known.has(id)) delete next.lists[id];
  return next;
}
