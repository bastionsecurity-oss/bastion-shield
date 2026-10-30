// Bastion Shield — human-readable names for ids that appear in activity data
// and rule matches: list ids, ruleset ids, resource types, activity kinds and
// dynamic-rule id ranges (docs/ARCHITECTURE.md §4.6).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityKind, BuildMeta, BuiltList, ListCategory } from '../../shared/types.ts';
import { RULE_ID, RULESET_PARAMS, REGEX_RULESET_SUFFIX } from '../../shared/constants.ts';
import { localized, t } from './i18n.ts';

export const CATEGORY_ORDER: ListCategory[] = ['ads', 'privacy', 'security', 'annoyances', 'regional'];

const CATEGORY_KEYS: Record<string, string> = {
  ads: 'catAds',
  privacy: 'catPrivacy',
  security: 'catSecurity',
  annoyances: 'catAnnoyances',
  regional: 'catRegional',
  custom: 'catCustom',
  unknown: 'catUnknown',
};

export function categoryLabel(cat: string | null | undefined): string {
  return t(CATEGORY_KEYS[cat ?? 'unknown'] ?? 'catUnknown');
}

const KIND_KEYS: Record<ActivityKind, string> = {
  blocked: 'kindBlocked',
  redirected: 'kindRedirected',
  stripped: 'kindStripped',
  debounced: 'kindDebounced',
  strict: 'kindStrict',
};
export const KINDS: ActivityKind[] = ['blocked', 'redirected', 'stripped', 'debounced', 'strict'];

export function kindLabel(kind: string): string {
  return t(KIND_KEYS[kind as ActivityKind] ?? 'kindBlocked');
}

const TYPE_KEYS: Record<string, string> = {
  main_frame: 'typeMainFrame',
  sub_frame: 'typeSubFrame',
  stylesheet: 'typeStylesheet',
  script: 'typeScript',
  image: 'typeImage',
  font: 'typeFont',
  object: 'typeObject',
  xmlhttprequest: 'typeXhr',
  ping: 'typePing',
  csp_report: 'typeCspReport',
  media: 'typeMedia',
  websocket: 'typeWebsocket',
  webtransport: 'typeWebtransport',
  webbundle: 'typeWebbundle',
  other: 'typeOther',
};
export const RESOURCE_TYPES = Object.keys(TYPE_KEYS);

export function typeLabel(type: string): string {
  const key = TYPE_KEYS[type];
  return key ? t(key) : type;
}

/** Lookup helpers over dist/rulesets/meta.json. Tolerates a missing file. */
export class ListDirectory {
  readonly meta: BuildMeta | null;
  private byId = new Map<string, BuiltList>();

  constructor(meta: BuildMeta | null) {
    this.meta = meta;
    for (const l of meta?.lists ?? []) this.byId.set(l.id, l);
  }

  get(listId: string | null | undefined): BuiltList | undefined {
    return listId ? this.byId.get(listId) : undefined;
  }

  /** Display name for a list id; built-ins and unknown ids get a readable fallback. */
  name(listId: string | null | undefined): string {
    if (!listId) return '';
    const l = this.byId.get(listId);
    if (l) return localized(l.name);
    if (listId === RULESET_PARAMS) return t('listParams');
    if (listId === 'custom' || listId === 'user') return t('listCustom');
    if (listId === 'admin') return t('listAdmin');
    if (listId === 'my-lists') return t('myListsTitle');
    return listId;
  }

  category(listId: string | null | undefined): ListCategory | 'unknown' {
    return this.get(listId)?.category ?? (listId === 'custom' || listId === 'my-lists' ? 'custom' : 'unknown');
  }

  /** Static ruleset id → list id (main and .regex companions). */
  listOfRuleset(rulesetId: string): string {
    const mapped = this.meta?.rulesetToList?.[rulesetId];
    if (mapped) return mapped;
    return rulesetId.endsWith(REGEX_RULESET_SUFFIX) ? rulesetId.slice(0, -REGEX_RULESET_SUFFIX.length) : rulesetId;
  }
}

/**
 * Name for a matched dynamic/session rule, by id range. The service worker
 * numbers grouped system rules consecutively from each base id
 * (SITES_DISABLED + n for nested "protection off" groups, STANDARD_1P_ALLOW + n
 * for Standard-mode groups, SESSION_SITES_DISABLED_NO_TAB + n), so match the
 * whole slot range, not only the base id.
 */
export function dynamicRuleLabel(rulesetId: string, ruleId: number): string {
  if (rulesetId === '_session') {
    if (ruleId >= RULE_ID.SESSION_PROCEED_START && ruleId <= RULE_ID.SESSION_PROCEED_END) return t('ruleProceed');
    if (ruleId >= RULE_ID.SESSION_BISECT_START && ruleId <= RULE_ID.SESSION_BISECT_END) return t('nerdBisectRuleLabel');
    if (ruleId >= RULE_ID.SESSION_SITES_DISABLED_NO_TAB && ruleId < RULE_ID.SESSION_PROCEED_START) return t('ruleSiteOff');
    return t('ruleSession');
  }
  if (ruleId >= RULE_ID.CUSTOM_START && ruleId <= RULE_ID.CUSTOM_END) return t('listCustom');
  if (ruleId >= RULE_ID.ADMIN_START && ruleId <= RULE_ID.ADMIN_END) return t('listAdmin');
  if (ruleId >= RULE_ID.MY_LISTS_START && ruleId <= RULE_ID.MY_LISTS_END) return t('myListsTitle');
  if (ruleId >= RULE_ID.DEBOUNCE_START && ruleId <= RULE_ID.DEBOUNCE_END) return t('ruleDebounce');
  if (ruleId >= RULE_ID.SITES_DISABLED && ruleId < RULE_ID.STANDARD_1P_ALLOW) return t('ruleSiteOff');
  if (ruleId >= RULE_ID.STANDARD_1P_ALLOW && ruleId < RULE_ID.GPC_HEADER) return t('ruleStandard1p');
  if (ruleId === RULE_ID.GPC_HEADER) return t('ruleGpc');
  if (ruleId >= RULE_ID.SITES_DISABLED_TOP && ruleId <= RULE_ID.SYSTEM_DYNAMIC_END) return t('ruleSiteOff');
  return t('ruleDynamic');
}
