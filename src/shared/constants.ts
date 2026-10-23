// Bastion Shield — shared constants. This file is part of the architecture
// contract (docs/ARCHITECTURE.md): the build tools, the compiler and the
// extension runtime all import from here, so values must stay in sync.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * DNR priority bands. Higher priority wins; on equal priority Chromium orders
 * allow > allowAllRequests > block > upgradeScheme > redirect > modifyHeaders.
 * See docs/ARCHITECTURE.md §4 for the rationale of every band.
 */
export const PRIORITY = {
  /** removeparam / csp / permissions modifiers, and their @@ exceptions (allow at 1 only beats other modifiers). */
  MODIFIER: 1,
  /** Brave query-filter stripping (redirect + queryTransform). Same band as modifiers. */
  PARAMS: 1,
  /** Block rules from "first-party protected" lists (Brave Standard semantics). */
  BLOCK_PROTECTED: 10,
  /** Redirect-resource rules from protected lists: 11 + min(7, $redirect=name:N). */
  REDIRECT_PROTECTED: 11,
  /** Standard-mode first-party allow (dynamic rule). Masks BLOCK_PROTECTED / REDIRECT_PROTECTED. */
  STANDARD_1P_ALLOW: 19,
  /**
   * First-party copy of modifiers ($removeparam/$csp/$permissions) from
   * always-apply lists and custom filters, so the Standard 1p allow (19) does
   * not cancel them on same-site subresources.
   */
  MODIFIER_1P: 20,
  /** Block rules from "always apply" lists (first-party lists, cookie/app-promo lists, user filters). */
  BLOCK_ALWAYS: 21,
  /**
   * Redirect-resource rules from always-apply lists: 22 + min(6, N). Also the
   * band for the third-party copy of protected-list redirects, so a stub is
   * served instead of an always-apply hard block (uBO/Brave behaviour).
   */
  REDIRECT_ALWAYS: 22,
  /** main_frame "strict block" redirects to pages/blocked.html. */
  STRICT_BLOCK: 29,
  /** @@ exception filters (any list). */
  ALLOW: 30,
  /**
   * Debounce (bounce-tracking) redirects to pages/bounce.html. Above list
   * exceptions and strict blocks so a known bounce tracker is skipped entirely
   * (Brave debounces before its ad-block engine runs), below $important.
   */
  DEBOUNCE: 35,
  /** $important block rules. */
  IMPORTANT: 40,
  /** $important redirect rules: 41 + min(8, N). */
  IMPORTANT_REDIRECT: 41,
  /**
   * `@@…$important` exceptions, user and admin custom filters only
   * (AdGuard-style; the list compiler and imported lists reject them). Above IMPORTANT (40) and
   * the whole IMPORTANT_REDIRECT band (41–49), so the user's important
   * exception beats any list block or redirect; below the per-site user
   * blocks and everything from PROCEED_ANYWAY up. `@@…$document,important`
   * becomes allowAllRequests at this priority.
   */
  IMPORTANT_ALLOW: 50,
  /**
   * Per-site "block scripts" fallback rules and other per-site user blocks
   * (reserved). Moved from 50 to 60 to make room for IMPORTANT_ALLOW.
   */
  SITE_USER_BLOCK: 60,
  /** Session allow after the user clicked "proceed anyway" on the blocked page. */
  PROCEED_ANYWAY: 900,
  /**
   * Nerd-mode filter bisect: session `allow` for the hosts let through in one
   * test reload (requestDomains + tabIds). Above every block, redirect and
   * $important band, below protection off and the GPC header (which still
   * applies). Does not lift cosmetic filters or scriptlets.
   */
  BISECT_ALLOW: 950,
  /** Per-site "protection off" (allowAllRequests, dynamic) and its tabId -1 companion (session). */
  SITE_DISABLED: 1000,
  /** Global Privacy Control request header (modifyHeaders set) — applies everywhere. */
  GPC_HEADER: 5000,
} as const;

/**
 * Rule-id ranges for dynamic and session rules (static rules are numbered per
 * ruleset starting at 1 and never collide with these).
 */
export const RULE_ID = {
  /** Dynamic: user custom filters (network part). */
  CUSTOM_START: 1,
  CUSTOM_END: 999_999,
  /** Dynamic: admin (managed policy) custom filters. */
  ADMIN_START: 1_000_000,
  ADMIN_END: 1_999_999,
  /** Dynamic: imported lists ("My lists"), one block of MY_LISTS.SLOT_SIZE ids per list slot. */
  MY_LISTS_START: 3_000_000,
  MY_LISTS_END: 4_999_999,
  /** Dynamic: debounce (bounce-tracking) regexSubstitution redirects. */
  DEBOUNCE_START: 2_000_000,
  DEBOUNCE_END: 2_000_999,
  /**
   * Dynamic: protection off for sites (allowAllRequests, main_frame only: the
   * setting follows the top-level site). While the managed kill switch
   * (ManagedPolicy.protectionEnabled false) is on, the same id is the global
   * allowAllRequests without a domain condition.
   */
  SITES_DISABLED: 8_000_000,
  /** Dynamic: Standard-mode first-party allow rule. */
  STANDARD_1P_ALLOW: 8_000_010,
  /** Dynamic: Aggressive-mode exceptions/inclusions (see ARCHITECTURE §4.3). */
  STANDARD_1P_ALLOW_SITES: 8_000_011,
  /** Dynamic: GPC header rule. */
  GPC_HEADER: 8_000_020,
  /** Session: tabId -1 (service worker / no-frame) allow for disabled sites. */
  SESSION_SITES_DISABLED_NO_TAB: 9_000_000,
  /** Session: proceed-anyway allows, one per (tab, host): 9_100_000 + n. */
  SESSION_PROCEED_START: 9_100_000,
  SESSION_PROCEED_END: 9_199_999,
  /**
   * Session: nerd-mode filter bisect test allows (background/nerd-bisect.ts),
   * a few per bisecting tab, ids picked from the free slots. apply.ts keeps
   * them like proceed rules, except on install and update.
   */
  SESSION_BISECT_START: 9_200_000,
  SESSION_BISECT_END: 9_209_999,
} as const;

/** Static ruleset id of the built-in Brave query-filter (tracking parameter stripping). */
export const RULESET_PARAMS = 'bastion-params';
/** Suffix of the companion static ruleset that holds a list's regexFilter rules. */
export const REGEX_RULESET_SUFFIX = '.regex';

/** Chromium limits we design against (docs/ARCHITECTURE.md §3). */
export const LIMITS = {
  GUARANTEED_STATIC_RULES: 30_000,
  MAX_ENABLED_STATIC_RULESETS: 50,
  MAX_STATIC_RULESETS: 100,
  /** Regex rules across all enabled static rulesets. */
  MAX_STATIC_REGEX_RULES: 1000,
  /** Regex rules shared by dynamic + session rules. */
  MAX_DYNAMIC_SESSION_REGEX_RULES: 1000,
  MAX_DYNAMIC_RULES: 30_000,
  MAX_UNSAFE_DYNAMIC_RULES: 5000,
  MAX_SESSION_RULES: 5000,
  /** getMatchedRules: 20 calls per 10 minutes without a user gesture. */
  GET_MATCHED_RULES_MIN_INTERVAL_MS: 35_000,
} as const;

/** Number of hostname shards for site-specific cosmetic data (dist/cosmetic/specific/NNN.json). */
export const COSMETIC_SHARDS = 256;

/**
 * Fingerprint seed files: SEED_SETS sets of SEED_FILES_PER_SET files
 * (dist/main/seeds/s<set>-<n>.js). One file per set is registered per browser
 * session: 16^16 = 2^64 combinations. The page must not be able to brute-force
 * the session key from farbled output (see main/farble.ts key derivation).
 */
export const SEED_SETS = 16;
export const SEED_FILES_PER_SET = 16;

/**
 * Whether an activity event (ActivityKind) stands for a request that never
 * loaded. Stripped parameters and debounced redirects change a request that
 * still goes out, so they save no data or time.
 */
export function savesRequest(kind: string): boolean {
  return kind !== 'stripped' && kind !== 'debounced';
}

/**
 * True for Bastion's own dynamic/session "system" rules (protection off,
 * Standard first-party allow, GPC header, proceed-anyway, bisect tests).
 * They are not filter-list matches and must not count as "blocked" or
 * "rules triggered".
 */
export function isSystemAllowRuleId(rulesetId: string, ruleId: number): boolean {
  if (rulesetId === '_dynamic') {
    return ruleId >= RULE_ID.SITES_DISABLED && ruleId <= RULE_ID.GPC_HEADER;
  }
  if (rulesetId === '_session') {
    return ruleId >= RULE_ID.SESSION_SITES_DISABLED_NO_TAB && ruleId <= RULE_ID.SESSION_BISECT_END;
  }
  return false;
}

/** chrome.storage.local keys (storage access level is TRUSTED_CONTEXTS only). */
export const STORAGE = {
  SETTINGS: 'settings',
  SITES: 'sites',
  CUSTOM_FILTERS: 'customFilters',
  TOTALS: 'totals',
  INSTALL: 'install',
  SEED_PICK: 'seedPick',
  /** Index of imported lists (MyListMeta[]); each text is stored under MY_LIST_PREFIX + id. */
  MY_LISTS: 'myLists',
  MY_LIST_PREFIX: 'myList:',
  /** Compiled copy of an imported list ({ s: stamp, c: JSON }), so a worker restart need not recompile it. */
  MY_LIST_COMPILED_PREFIX: 'myListCompiled:',
} as const;

/** Imported lists ("My lists"). */
export const MY_LISTS = {
  /** 20 slots of 100'000 ids fill RULE_ID.MY_LISTS_START … MY_LISTS_END. */
  MAX: 20,
  SLOT_SIZE: 100_000,
  /** Per list; HaGeZi Multi PRO is about 4.5 MB, EasyList about 2 MB. */
  MAX_BYTES: 10_000_000,
  /** Web-address lists are refetched when the last attempt is older than this. */
  UPDATE_AFTER_MS: 24 * 60 * 60 * 1000,
  MAX_URL_LENGTH: 2048,
  MAX_TITLE_LENGTH: 120,
} as const;

/** IndexedDB database used by the service worker for blocking history. */
export const IDB = {
  NAME: 'bastion-activity',
  VERSION: 1,
  STORE_EVENTS: 'events',
  STORE_DAILY: 'daily',
} as const;

/** Live log ring-buffer size per tab (memory + storage.session mirror). */
export const LIVE_EVENTS_PER_TAB = 300;
/** Hard cap on persisted history events (oldest dropped first). */
export const HISTORY_MAX_EVENTS = 50_000;

/** Port name used by popup/dashboard to receive live blocking events. */
export const PORT_LIVE = 'live';

/** Project links. Change REPO_URL when the public repository is created. */
export const LINKS = {
  REPO_URL: 'https://github.com/bastionsecurity-oss/bastion-shield',
  HOMEPAGE: 'https://bastionsecurity.ch',
  PRIVACY: 'https://github.com/bastionsecurity-oss/bastion-shield/blob/main/docs/PRIVACY.md',
  /** Incident contact form on bastionsecurity.ch («Cyber-Vorfall?»), German and English pages. */
  INCIDENT_DE: 'https://www.bastionsecurity.ch/kontakt#vorfall',
  INCIDENT_EN: 'https://www.bastionsecurity.ch/en/contact#vorfall',
} as const;
