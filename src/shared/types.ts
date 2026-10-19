// Bastion Shield — shared types. Part of the architecture contract
// (docs/ARCHITECTURE.md). Build tools write the dist/* data formats declared
// here; the service worker, content scripts and UI read them.
//
// SPDX-License-Identifier: GPL-3.0-or-later

// ---------------------------------------------------------------------------
// Filter list catalog (filters/catalog.json, copied to dist/rulesets/meta.json
// enriched with build results)
// ---------------------------------------------------------------------------

export type ListCategory = 'ads' | 'privacy' | 'security' | 'annoyances' | 'regional' | 'custom';

export interface CatalogList {
  /** Stable id, also the DNR static ruleset id. [a-z0-9-]+ */
  id: string;
  /** Display names; `de` is authoritative for German UI, `en` is the fallback. */
  name: { en: string; de: string; fr?: string; it?: string };
  description: { en: string; de: string; fr?: string; it?: string };
  category: ListCategory;
  /** Enabled on fresh install (regional lists: see `langs`). */
  default: boolean;
  /** Regional lists: enabled on install when the browser UI language matches. */
  langs?: string[];
  /**
   * Brave "first-party protections": in Standard mode, block/redirect rules of
   * this list do not apply to same-site requests. false = always applies.
   */
  firstPartyProtected: boolean;
  /** May use trusted scriptlets (trusted-*) and trusted redirect resources. */
  trusted: boolean;
  /** Emit main_frame "strict block" redirects (to pages/blocked.html) for plain ||host^ filters. */
  strictBlock: boolean;
  /** Source URLs, concatenated in order. Each may use !#include (resolved relative to its URL). */
  sources: CatalogSource[];
  homepage: string;
  /** SPDX expression or short licence label shown in the UI. */
  license: string;
  licenseUrl?: string;
  /** Attribution line shown on the About page. */
  attribution: string;
  /** Hidden lists are always on (user cannot toggle) unless an admin policy says otherwise. */
  locked?: boolean;
}

export interface CatalogSource {
  url: string;
  /** Local path relative to repo root instead of a URL (e.g. filters/bastion.txt). */
  path?: string;
  /** 'abp' (default) understands ABP/uBO syntax; 'hosts' = hosts-file format. */
  format?: 'abp' | 'hosts';
  /**
   * Per-source trust override. `false` on a source of a trusted list wraps it
   * in `!#trusted off/on <build secret>` so trusted-* scriptlets and trusted
   * redirect resources from that source are rejected (uBO's trust model:
   * only first-party-maintained sources may run arbitrary page code).
   */
  trusted?: boolean;
}

export interface Catalog {
  version: 1;
  lists: CatalogList[];
}

// ---------------------------------------------------------------------------
// dist/rulesets/meta.json — written by tools/build.ts
// ---------------------------------------------------------------------------

export interface BuiltList extends Omit<CatalogList, 'sources'> {
  /** Bit index (0..31) used in cosmetic/scriptlet data masks. */
  bit: number;
  sources: { url: string; sha256: string; bytes: number; version?: string; lastModified?: string }[];
  /** DNR static ruleset ids that belong to this list (main + optional `.regex`). */
  rulesetIds: string[];
  ruleCount: number;
  regexRuleCount: number;
  stats: {
    filters: number;
    network: number;
    cosmetic: number;
    scriptlets: number;
    unsupported: number;
    badfiltered: number;
  };
}

export interface BuildMeta {
  /** ISO date-time of the build. */
  builtAt: string;
  extensionVersion: string;
  lists: BuiltList[];
  /** Static ruleset id -> list id (main and regex companions, plus RULESET_PARAMS -> 'bastion-params'). */
  rulesetToList: Record<string, string>;
  /** Redirect resource name/alias -> extension path, e.g. "noop.js" -> "/war/noop.js". */
  redirectResources: Record<string, string>;
  vendor: { ublock: string; braveResources: string; braveLists: string };
}

/**
 * dist/rulesets/filters/<rulesetId>.json — transparency map: index = rule id,
 * value = original filter text(s). Merged rules list up to 20 filters and a
 * "+N more" marker. Loaded lazily by the UI only.
 */
export type RuleSourceMap = (string[] | null)[];

// ---------------------------------------------------------------------------
// Cosmetic data (dist/cosmetic/*) — written by tools, read by the service worker
// ---------------------------------------------------------------------------

/**
 * dist/cosmetic/specific/<NNN>.json where NNN = shardOf(hostKey) zero-padded
 * to 3 digits. hostKey is a hostname ("example.com"), an entity ("google.*")
 * or "*" never (generic data lives elsewhere).
 */
export interface CosmeticShard {
  /** hostKey -> entries */
  hosts: Record<string, CosmeticHostEntry[]>;
}

/**
 * [kind, payload, listMask]
 * kind: 0 = hide selector (display:none!important)
 *       1 = hide exception (#@#selector) — removes the same selector, incl. generic ones
 *       2 = procedural filter (payload = JSON string of ProceduralFilter)
 *       3 = style injection (payload = "selector { decl }" CSS rule text, from :style())
 *       4 = flags (payload = "generichide" | "specifichide" | "elemhide" | "noscriptlets")
 *       5 = procedural exception (payload = original procedural selector text)
 */
export type CosmeticHostEntry = [kind: 0 | 1 | 2 | 3 | 4 | 5, payload: string, listMask: number];

/**
 * dist/cosmetic/generic.json — lowly generic selectors keyed by their
 * id/class token ("#ad_box", ".ad-banner"), surveyed in the page.
 * Layout (still plain JSON): `{"tokens":{` and `}}` on their own lines and
 * one `"token":[...]` entry per line in between, sorted by token in UTF-16
 * code unit order. The service worker binary-searches the text and parses
 * only the entries of tokens it looks up (background/cosmetic.ts
 * genericLookupFromText).
 */
export interface GenericIndex {
  /** token -> [selector, listMask][] */
  tokens: Record<string, [string, number][]>;
  /** Selectors that are excepted globally by `#@#sel` without hostname are removed at build time. */
}

/**
 * dist/cosmetic/meta.json
 */
export interface CosmeticMeta {
  shards: number;
  /** listId -> path of its highly generic CSS file (registered as a content-script css) or null. */
  genericHighCss: Record<string, string | null>;
  /**
   * listId -> hostnames where that list's highly-generic CSS must NOT be
   * injected statically (hosts with #@# exceptions that target its highly
   * generic selectors, and its `~host` exclusions). The SW registers ONE
   * generic-high CSS registration for all enabled lists, excluding the union
   * of these sets of enabled lists plus `genericHideHosts`; on those hosts it
   * injects a filtered copy of every enabled list's selectors instead.
   * Match-pattern hosts only (no entities, no bare labels).
   */
  genericHighExcludedHosts: Record<string, string[]>;
  /** Hosts with $generichide / $elemhide in any list (excluded for every list). */
  genericHideHosts?: string[];
  /** listId -> highly generic selectors (needed for the filtered copy). */
  genericHighSelectorsFile: string;
}

// ---------------------------------------------------------------------------
// Scriptlets (dist/scriptlets/*)
// ---------------------------------------------------------------------------

/**
 * One list's scriptlet data for one world (dist/scriptlets/<listId>-<world>.js).
 * Not a Chrome registration by itself: the SW lists the data files of the
 * enabled lists in the world's single bundle registration (ScriptletBundle).
 */
export interface ScriptletRegistration {
  /** Unique id: `sl-<listId>-<world>` (world lower-case). */
  id: string;
  listId: string;
  world: 'MAIN' | 'ISOLATED';
  /** Data file path relative to the extension root. */
  file: string;
  /** Always ["<all_urls>"]: hostnames are matched in the bundle's runner. */
  matches: string[];
}

/**
 * Per world: the registration `js` is [core, data files of enabled lists, end].
 * The core declares every scriptlet function once and hands it over on a
 * per-build secret global; the end file reads and deletes it, looks up the
 * frame's hostname in the data and runs the matching scriptlets.
 */
export interface ScriptletBundle {
  world: 'MAIN' | 'ISOLATED';
  /** Must be first in `js`. */
  core: string;
  /** Must be last in `js`. */
  end: string;
}

/**
 * The data of several lists in one file (the usual default set). Used
 * instead of their own data files when every list in `lists` is enabled:
 * one file and one lookup per frame instead of one per list.
 */
export interface ScriptletMerged {
  world: 'MAIN' | 'ISOLATED';
  /** Lists merged; each also has its own data file for this world. */
  lists: string[];
  file: string;
}

export interface ScriptletIndex {
  /** Data files, sorted by id. */
  registrations: ScriptletRegistration[];
  /** One per world that has scriptlets (written by every build; absent = no scriptlets). */
  bundles?: ScriptletBundle[];
  merged?: ScriptletMerged[];
}

// ---------------------------------------------------------------------------
// Settings & per-site settings (chrome.storage.local, TRUSTED_CONTEXTS only)
// ---------------------------------------------------------------------------

export type BlockingMode = 'standard' | 'aggressive';
export type FingerprintLevel = 'off' | 'standard' | 'strict';
export type WebRtcPolicy = 'default' | 'default_public_interface_only' | 'disable_non_proxied_udp';

export interface Settings {
  version: 1;
  defaultMode: BlockingMode;
  /** listId -> enabled. Missing ids fall back to the catalog default. */
  lists: Record<string, boolean>;
  privacy: {
    /** Send Sec-GPC: 1 and expose navigator.globalPrivacyControl. Default true (Brave: always on). */
    gpc: boolean;
    /** Strip Brave's tracking query parameters on cross-site navigations. Default true. */
    stripParams: boolean;
    /** Bounce-tracking protection (Brave debounce rules). Default true. */
    debounce: boolean;
    /** Redirect AMP pages to their canonical URL. Default true. */
    deAmp: boolean;
    /** Default fingerprinting protection for sites. Default 'standard'. */
    fingerprinting: FingerprintLevel;
    /** chrome.privacy.websites.hyperlinkAuditingEnabled = false. Default true (= block <a ping>). */
    blockHyperlinkAuditing: boolean;
    /** chrome.privacy.network.webRTCIPHandlingPolicy. Default 'default' (browser default). */
    webrtcPolicy: WebRtcPolicy;
    /** chrome.privacy.websites.thirdPartyCookiesAllowed; null = leave the browser setting alone. Default null. */
    blockThirdPartyCookies: boolean | null;
    /** Turn off Topics / Protected Audience / Attribution reporting via chrome.privacy. Default true. */
    disablePrivacySandboxAds: boolean;
    /** ClickFix protection: stop pages from putting hidden commands (powershell, mshta, curl | sh …) on the clipboard. Default true. */
    clipboardGuard: boolean;
  };
  ui: {
    /** Toolbar badge with the per-tab blocked count. Default true. */
    badge: boolean;
    /** Record live per-tab activity (webRequest observers). Default true. */
    activityLog: boolean;
    /** «Cyber-Vorfall?» button (link to bastionsecurity.ch) in popup and navigation. Default true. */
    incidentCta: boolean;
    /** UI language: 'de' | 'en' | 'fr' | 'it', or 'auto' (browser language; English when it is none of these). Default 'auto'. */
    language: 'auto' | 'de' | 'en' | 'fr' | 'it';
  };
  history: {
    /** Persist blocking history (IndexedDB, local only). Default true. */
    enabled: boolean;
    /** Days to keep history. Default 30. 0 = keep only today's aggregate. */
    retentionDays: number;
  };
  /**
   * Nerd mode: power-user tools and experimental guards. Every feature below
   * runs only while `enabled` is true (docs/NERD-MODE.md).
   */
  nerd: {
    /** Master switch. Default false. */
    enabled: boolean;
    /** «Bastion Shield» entry in the page/link/selection context menu. Default true. */
    contextMenu: boolean;
    /** Filter history links («GitHub ↗») in the popup, Activity and the Lab's results. Default true. */
    filterHistory: boolean;
    /** Count fingerprinting API calls per page (MAIN-world meter). Default true. */
    fingerprintMeter: boolean;
    /** Warn on lookalike domains of protected domains. Default true. */
    lookalike: boolean;
    /** User's protected domains (registrable domains, lower-case, punycode). Policy adds its own. */
    protectedDomains: string[];
  };
}

export interface SiteSettings {
  /** false = protection off on this site (allowAllRequests). Missing = on. */
  enabled?: boolean;
  mode?: BlockingMode;
  /** Block JavaScript on this site (chrome.contentSettings.javascript). */
  blockScripts?: boolean;
  fingerprinting?: FingerprintLevel;
}

/** Key = site key: hostname, lower-case, punycode, leading "www." removed. */
export type SitesMap = Record<string, SiteSettings>;

// ---------------------------------------------------------------------------
// Managed policy (chrome.storage.managed, schema in policy/managed_schema.json)
// Every key is optional. Present keys override user values and lock the
// corresponding UI control.
// ---------------------------------------------------------------------------

export interface ManagedPolicy {
  organizationName?: string;
  supportUrl?: string;
  supportEmail?: string;
  defaultMode?: BlockingMode;
  /** listId -> enabled (forced). */
  lists?: Record<string, boolean>;
  /** If true, users cannot change any list (including ones not mentioned in `lists`). */
  lockLists?: boolean;
  /** Hostnames where protection is forced off. */
  disabledSites?: string[];
  /** Hostnames forced to aggressive mode. */
  aggressiveSites?: string[];
  /** Admin filters in uBO/ABP syntax (network + cosmetic; scriptlets need a release). */
  customFilters?: string[];
  /** Allow users to switch protection off per site. Default true. */
  allowUserSiteToggle?: boolean;
  /** Allow users to edit their own custom filters. Default true. */
  allowUserFilters?: boolean;
  /** Lock all settings shown in the dashboard. */
  lockSettings?: boolean;
  gpc?: boolean;
  stripParams?: boolean;
  debounce?: boolean;
  deAmp?: boolean;
  fingerprinting?: FingerprintLevel;
  blockHyperlinkAuditing?: boolean;
  webrtcPolicy?: WebRtcPolicy;
  blockThirdPartyCookies?: boolean;
  disablePrivacySandboxAds?: boolean;
  showBadge?: boolean;
  activityLog?: boolean;
  /** «Cyber-Vorfall?» button in popup and navigation. Default true. */
  showIncidentCta?: boolean;
  historyEnabled?: boolean;
  historyRetentionDays?: number;
  /**
   * 'github' (prefilled public issue), 'email' (supportEmail), 'none' (hide the button).
   * Default: 'email' when supportEmail is set, otherwise 'github'.
   */
  reportBrokenSite?: 'github' | 'email' | 'none';
  /** Forces nerd mode on or off (nerd.enabled). */
  nerdMode?: boolean;
  /** Forces ClickFix protection on or off (privacy.clipboardGuard). */
  clipboardGuard?: boolean;
  /** Registrable domains protected by the lookalike warning, added to the user's own. */
  protectedDomains?: string[];
  /**
   * Fleet-wide emergency switch. false = all filtering, cosmetic and privacy
   * scripts off everywhere (allowAllRequests for every site, registrations
   * removed, privacy API overrides released). Missing or true = normal.
   */
  protectionEnabled?: boolean;
}

/** What the UI needs to render lock icons. */
export interface EffectiveConfig {
  settings: Settings;
  managed: ManagedPolicy;
  /** Dotted setting paths that are locked by policy, e.g. "privacy.gpc", "lists.easylist", "defaultMode". */
  locked: string[];
}

// ---------------------------------------------------------------------------
// Activity (live log + history)
// ---------------------------------------------------------------------------

export type ActivityKind =
  | 'blocked' // DNR block (ERR_BLOCKED_BY_CLIENT)
  | 'redirected' // DNR redirect to a neutered resource (web_accessible_resources)
  | 'stripped' // query parameters removed
  | 'debounced' // bounce tracker skipped
  | 'strict'; // main_frame navigation sent to the blocked page

export interface ActivityEvent {
  /** ms since epoch */
  t: number;
  tabId: number;
  frameId: number;
  kind: ActivityKind;
  /** Request URL. History stores it without query/fragment. */
  url: string;
  /** Request hostname. */
  host: string;
  /** chrome.webRequest.ResourceType */
  type: string;
  /** Site key of the tab's top-level page at the time of the request. */
  site: string;
  /** Third party relative to the page (by registrable-domain approximation). */
  thirdParty: boolean;
  /** Attributed list id, when known (via getMatchedRules). */
  list?: string;
  /** Attributed rule (rulesetId:ruleId), when known. */
  rule?: string;
}

export interface DailyAggregate {
  /** YYYY-MM-DD in local time. */
  day: string;
  total: number;
  byKind: Partial<Record<ActivityKind, number>>;
  byCategory: Partial<Record<ListCategory | 'unknown', number>>;
  /** Blocked hostname -> count (top 500 kept). */
  byHost: Record<string, number>;
  /** Site where blocking happened -> count (top 500 kept). */
  bySite: Record<string, number>;
  byType: Record<string, number>;
}

export interface Totals {
  since: number;
  blocked: number;
  byKind: Partial<Record<ActivityKind, number>>;
}

// ---------------------------------------------------------------------------
// Messages (chrome.runtime.sendMessage). Every message has a `type`.
// Responses are plain JSON. See docs/ARCHITECTURE.md §7.
// ---------------------------------------------------------------------------

/** Content script (isolated) -> SW, once per frame at document_start. */
export interface MsgCosmeticFrame {
  type: 'cosmetic:frame';
  url: string;
  /** Top-level page URL as seen by the frame (location.ancestorOrigins fallback). */
  topUrl?: string;
}
export interface MsgCosmeticFrameResponse {
  /** Protection is off for this site: do nothing. */
  off: boolean;
  /** Specific hide + :style() CSS already inserted by the SW (USER origin); content script also adopts it for speed. */
  css: string;
  /** Procedural filters as JSON strings (ProceduralFilter). Empty = no engine needed. */
  procedural: string[];
  /** Run the generic class/id surveyor. */
  generic: boolean;
  /** Redirect AMP documents to canonical. */
  deAmp: boolean;
  /** Top frame only, nerd mode: this host looks like a protected domain. */
  lookalike?: LookalikeHit | null;
}

/** Content script -> SW: newly seen id/class tokens ("#foo", ".bar"). */
export interface MsgCosmeticTokens {
  type: 'cosmetic:tokens';
  url: string;
  tokens: string[];
}
export interface MsgCosmeticTokensResponse {
  css: string;
}

/** Content script -> SW: inject content/procedural.js into this frame. */
export interface MsgProceduralInject {
  type: 'cosmetic:procedural';
}

/** pages/blocked.html -> SW */
export interface MsgBlockedInfo {
  type: 'blocked:info';
}
export interface MsgBlockedInfoResponse {
  url: string | null;
  host: string | null;
  listId: string | null;
  listName: string | null;
  category: ListCategory | null;
}
export interface MsgBlockedProceed {
  type: 'blocked:proceed';
  url: string;
}

/** Popup -> SW */
export interface MsgPopupState {
  type: 'popup:state';
  tabId: number;
}
export interface PopupState {
  tabId: number;
  url: string | null;
  host: string | null;
  site: string | null;
  /** false for chrome://, edge://, extension pages, store pages, etc. */
  filterable: boolean;
  siteSettings: Required<Pick<SiteSettings, 'enabled' | 'mode' | 'blockScripts' | 'fingerprinting'>>;
  /** Counts for the current page load. `redirected` = surrogate stubs served; `debounced` = bounce trackers skipped. */
  counts: { blocked: number; redirected: number; stripped: number; debounced: number; thirdPartyHosts: number };
  totals: Totals;
  /** Latest events for this tab (newest last). */
  recent: ActivityEvent[];
  /** Live activity log is on (individual events are recorded and shown). */
  logging: boolean;
  /** Per-tab counters are maintained (activity log on, or SW-maintained badge). */
  counting: boolean;
  /** Global kill switch from managed policy: protection is off everywhere. */
  globallyDisabled: boolean;
  /** siteToggle: protection switch locked; mode: blocking mode locked by policy (e.g. aggressiveSites); settings: lockSettings. */
  locks: { siteToggle: boolean; mode: boolean; settings: boolean };
  managed: { organizationName?: string; reportBrokenSite: 'github' | 'email' | 'none'; supportEmail?: string; supportUrl?: string };
  /** Show the «Cyber-Vorfall?» button (settings ui.incidentCta). */
  incidentCta: boolean;
  /** Nerd mode data for this tab; null while nerd mode is off. */
  nerd: NerdTabState | null;
  version: string;
}

// ---------------------------------------------------------------------------
// Nerd mode (docs/NERD-MODE.md)
// ---------------------------------------------------------------------------

/** Fingerprinting vectors counted by the MAIN-world meter. */
export type FpVector = 'canvas' | 'webgl' | 'audio' | 'fonts' | 'navigator' | 'screen' | 'media' | 'timing';

export interface LookalikeHit {
  /** The visited hostname. */
  host: string;
  /** The protected registrable domain it imitates. */
  target: string;
  /** Why: 'homoglyph' (confusable characters / punycode), 'typo' (edit distance), 'combo' (target label plus extra words). */
  reason: 'homoglyph' | 'typo' | 'combo';
}

/** One bisect candidate: a hostname blocked on the tab, with the rules that blocked it. */
export interface BisectCandidate {
  host: string;
  /** "rulesetId:ruleId" attributions seen for this host (may be empty). */
  rules: string[];
  /** Requests blocked for this host on the page load the bisect started from. */
  count: number;
}

/** What the popup shows for a running or finished bisect. */
export interface BisectView {
  tabId: number;
  site: string;
  /** testing: waiting for "works now?"; found: one candidate left; clean: still broken with everything allowed (not a network block); cancelled. */
  phase: 'testing' | 'found' | 'clean' | 'cancelled';
  /** 1-based step and the worst-case number of steps. */
  step: number;
  maxSteps: number;
  /** Candidates still in play. */
  remaining: number;
  /** Hosts currently let through on this tab for the test reload. */
  allowed: string[];
  /** Set when phase is 'found'. */
  culprit?: BisectCandidate & { filters: string[]; lists: string[] };
  /**
   * Further hosts the page needs let through together with the culprit
   * (interacting blocks), phase 'found' only. "Keep" adds an exception for each.
   */
  also?: (BisectCandidate & { filters: string[]; lists: string[] })[];
  /** The interacting hosts could not be fully separated: `culprit` + `also` is a working superset. */
  partial?: boolean;
}

export interface NerdTabState {
  /** Fingerprinting API calls on the current page load, per vector (meter on). */
  fp: Partial<Record<FpVector, number>> | null;
  /** Dangerous clipboard writes replaced on this tab since the last navigation. */
  clipboardBlocked: number;
  /** Lookalike warning shown on this page. */
  lookalike: LookalikeHit | null;
  /** Running or last bisect on this tab. */
  bisect: BisectView | null;
}

/**
 * Blocker notices (content/notice.ts). A subframe's cosmetic.js sends a
 * blocked clipboard text to the SW (`notice:clip`), which forwards it to the
 * tab's top frame as `notice:show` (chrome.tabs.sendMessage, frameId 0):
 * notices render in the top frame only.
 */
export interface MsgNoticeClip {
  type: 'notice:clip';
  text: string;
  source: 'ubo' | 'bastion';
}

/** SW -> top frame (chrome.tabs.sendMessage); see MsgNoticeClip. */
export interface MsgNoticeShow {
  type: 'notice:show';
  text: string;
  source: 'ubo' | 'bastion';
}

/** Content relay (ISOLATED) -> SW. */
export type MsgNerdSignal =
  | { type: 'nerd:signal'; kind: 'fp'; counts: Partial<Record<FpVector, number>> }
  | { type: 'nerd:signal'; kind: 'clip'; sample: string };

/**
 * Popup / commands -> SW. `works` answers "does the page work now?" for
 * action 'answer'. Two helpers share the bisect's data: 'hosts' lists the
 * hosts blocked on the tab's page load (filter texts with `describe`), and
 * 'allow' adds a narrow exception for `host` on the tab's site.
 */
export interface MsgNerdBisect {
  type: 'nerd:bisect';
  action: 'start' | 'answer' | 'cancel' | 'state' | 'keep' | 'allow' | 'hosts';
  tabId: number;
  works?: boolean;
  host?: string;
  describe?: boolean;
}

/** One host blocked on a tab's page load (nerd:bisect 'hosts'). */
export interface NerdBlockedHost extends BisectCandidate {
  /** Filter texts (transparency map), only with `describe`. */
  filters: string[];
  lists: string[];
}

export interface MsgSiteSet {
  type: 'site:set';
  site: string;
  patch: SiteSettings;
  /** Reload the tab after applying. */
  reloadTabId?: number;
}

/** Dashboard -> SW */
export interface MsgConfigGet { type: 'config:get' }
export interface MsgSettingsSet { type: 'settings:set'; patch: DeepPartial<Settings> }
export interface MsgListsGet { type: 'lists:get' }
export interface ListsState {
  meta: BuildMeta;
  enabled: Record<string, boolean>;
  /** Static rule budget. */
  budget: { used: number; available: number | null; regexUsed: number };
  locked: string[];
  /** listId -> error string if enabling failed. */
  errors: Record<string, string>;
}
export interface MsgListsSet { type: 'lists:set'; listId: string; enabled: boolean }
export interface MsgSitesGet { type: 'sites:get' }
export interface MsgSitesSet { type: 'sites:set'; sites: SitesMap }
export interface MsgCustomGet { type: 'custom:get' }
export interface CustomState {
  text: string;
  admin: string[];
  /** Result of the last compile. */
  report: { network: number; cosmetic: number; scriptletsIgnored: number; errors: { line: number; text: string; reason: string }[] };
  locked: boolean;
}
export interface MsgCustomSet { type: 'custom:set'; text: string }
export interface MsgHistoryQuery { type: 'history:query'; fromDay: string; toDay: string }
export interface HistoryResult { days: DailyAggregate[]; totals: Totals }
export interface MsgHistoryEvents { type: 'history:events'; limit: number; before?: number; site?: string; host?: string }
export interface MsgHistoryClear { type: 'history:clear' }
export interface MsgBackupExport { type: 'backup:export' }
export interface MsgBackupImport { type: 'backup:import'; data: BackupFile }
export interface BackupFile {
  format: 'bastion-shield-backup';
  version: 1;
  exportedAt: string;
  settings: Settings;
  sites: SitesMap;
  customFilters: string;
}

/** Live port (name PORT_LIVE). Client sends {subscribe: tabId | 'all'}; SW posts LivePortMessage. */
export interface LiveSubscribe { subscribe: number | 'all' }
export type LivePortMessage =
  | { type: 'backlog'; events: ActivityEvent[] }
  | { type: 'event'; event: ActivityEvent }
  | { type: 'reset'; tabId: number }
  /** List attribution that arrived after the event was streamed (getMatchedRules join). */
  | { type: 'attributed'; updates: { t: number; tabId: number; url: string; kind: ActivityKind; list: string; rule?: string }[] };

/**
 * Response shapes (every handler may instead answer `{ error: string }`):
 * - cosmetic:frame → MsgCosmeticFrameResponse; cosmetic:tokens → MsgCosmeticTokensResponse
 * - cosmetic:procedural, blocked:proceed, history:clear → { ok: true }
 * - blocked:info → MsgBlockedInfoResponse; popup:state → PopupState
 * - site:set → { ok: true; ignored: string[]; siteSettings: SiteSettings }
 * - config:get → EffectiveConfig; settings:set, backup:import → EffectiveConfig & { ignored: string[] }
 * - lists:get, lists:set → ListsState; custom:get, custom:set → CustomState
 * - sites:get, sites:set → { sites: SitesMap } (the user's own map; policy entries are reported via EffectiveConfig)
 * - history:query → HistoryResult; history:events → { events: ActivityEvent[] }
 * - backup:export → BackupFile
 * - nerd:signal → { ok: true }; nerd:bisect → { bisect: BisectView | null } (action 'keep' turns the culprit into a custom exception filter),
 *   'hosts' → { hosts: NerdBlockedHost[] }, 'allow' → { added: string[] }
 * - notice:clip → { ok: true } (forwarded to the tab's top frame as MsgNoticeShow)
 *
 * EffectiveConfig.locked paths: "defaultMode", "privacy.<key>", "ui.badge", "ui.activityLog",
 * "history.enabled", "history.retentionDays", "nerd.<key>", "lists.<id>", plus the pseudo-paths "lists"
 * (all lists locked), "sites.enabled" (users may not switch protection off) and
 * "customFilters" (user filters read-only).
 */
export type Message =
  | MsgCosmeticFrame
  | MsgCosmeticTokens
  | MsgProceduralInject
  | MsgBlockedInfo
  | MsgBlockedProceed
  | MsgPopupState
  | MsgSiteSet
  | MsgConfigGet
  | MsgSettingsSet
  | MsgListsGet
  | MsgListsSet
  | MsgSitesGet
  | MsgSitesSet
  | MsgCustomGet
  | MsgCustomSet
  | MsgHistoryQuery
  | MsgHistoryEvents
  | MsgHistoryClear
  | MsgBackupExport
  | MsgBackupImport
  | MsgNerdSignal
  | MsgNerdBisect
  | MsgNoticeClip;

export type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

// ---------------------------------------------------------------------------
// Procedural cosmetic filters (content/procedural.ts)
// ---------------------------------------------------------------------------

/**
 * A compiled procedural filter. `selector` is the leading plain CSS selector
 * (may be "" for operators starting at :root). `tasks` are applied in order.
 * `action` is applied to the final element set (default: hide).
 */
export interface ProceduralFilter {
  /** Original filter text for debugging/logging. */
  raw: string;
  selector: string;
  tasks: ProceduralTask[];
  action?: ['style', string] | ['remove'] | ['remove-attr', string] | ['remove-class', string];
}

export type ProceduralTask =
  | ['has', ProceduralFilter]
  | ['has-text', string] // "/regex/flags" or plain text
  | ['if', ProceduralFilter]
  | ['if-not', ProceduralFilter]
  | ['not', ProceduralFilter]
  | ['matches-attr', string]
  | ['matches-css', string]
  | ['matches-css-before', string]
  | ['matches-css-after', string]
  | ['matches-media', string]
  | ['matches-path', string]
  | ['matches-prop', string]
  | ['min-text-length', number]
  | ['others']
  | ['shadow', string]
  | ['spath', string]
  | ['upward', number | string]
  | ['watch-attr', string]
  | ['xpath', string];
