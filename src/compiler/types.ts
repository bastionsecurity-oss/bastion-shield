// Bastion filter compiler — public types. The compiler is environment-agnostic
// TypeScript (no Node or DOM APIs) so the same code runs in tools/build.ts at
// build time and in the extension (custom filters) at runtime.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/** Subset of chrome.declarativeNetRequest.Rule we emit (plain JSON). `id` is assigned by the caller. */
export interface DnrRule {
  id?: number;
  priority?: number;
  action: DnrAction;
  condition: DnrCondition;
}

export interface DnrAction {
  type: 'block' | 'allow' | 'allowAllRequests' | 'redirect' | 'modifyHeaders' | 'upgradeScheme';
  redirect?: {
    extensionPath?: string;
    url?: string;
    regexSubstitution?: string;
    transform?: {
      scheme?: string;
      host?: string;
      path?: string;
      query?: string;
      queryTransform?: { removeParams?: string[]; addOrReplaceParams?: { key: string; value: string; replaceOnly?: boolean }[] };
      fragment?: string;
    };
  };
  requestHeaders?: DnrHeaderOp[];
  responseHeaders?: DnrHeaderOp[];
}

export interface DnrHeaderOp {
  header: string;
  operation: 'append' | 'set' | 'remove';
  value?: string;
}

export interface DnrCondition {
  urlFilter?: string;
  regexFilter?: string;
  isUrlFilterCaseSensitive?: boolean;
  requestDomains?: string[];
  excludedRequestDomains?: string[];
  initiatorDomains?: string[];
  excludedInitiatorDomains?: string[];
  topDomains?: string[];
  excludedTopDomains?: string[];
  domainType?: 'firstParty' | 'thirdParty';
  resourceTypes?: string[];
  excludedResourceTypes?: string[];
  requestMethods?: string[];
  excludedRequestMethods?: string[];
  responseHeaders?: { header: string; values?: string[]; excludedValues?: string[] }[];
  excludedResponseHeaders?: { header: string; values?: string[]; excludedValues?: string[] }[];
  tabIds?: number[];
}

export interface ScriptletInfo {
  /** Canonical name, e.g. "set-constant.js". */
  name: string;
  world: 'MAIN' | 'ISOLATED';
  requiresTrust: boolean;
}

export interface CompileOptions {
  listId: string;
  /** Allow trusted-* scriptlets and redirect resources that require trust. */
  trusted: boolean;
  /** Brave Standard semantics: use the *_PROTECTED priority bands. false = *_ALWAYS bands. */
  firstPartyProtected: boolean;
  /** Emit main_frame strict-block redirect rules for plain hostname filters. */
  strictBlock: boolean;
  /** Preprocessor tokens that evaluate to true in `!#if` (see DEFAULT_ENV). */
  env?: ReadonlySet<string>;
  /** Redirect resource name or alias -> extension path ("/war/noop.js"). Missing name = filter rejected. */
  redirectResources: ReadonlyMap<string, { path: string; requiresTrust: boolean }>;
  /** Scriptlet name or alias (with or without ".js") -> canonical info. Missing name = filter rejected. */
  scriptlets: ReadonlyMap<string, ScriptletInfo>;
  /** Global $badfilter set from collectBadfilters() over all lists. */
  badfilters?: ReadonlySet<string>;
  /** Extension path of the strict-block page. Default "/pages/blocked.html". */
  blockedPagePath?: string;
  /** Hosts-file parsing for the whole text. */
  format?: 'abp' | 'hosts';
  /** Keep at most this many rejected-filter samples in stats.rejected. Default 200. */
  maxRejectedSamples?: number;
  /**
   * Also emit a first-party copy (priority PRIORITY.MODIFIER_1P, domainType
   * firstParty) of $removeparam/$csp/$permissions rules, so the Standard-mode
   * first-party allow (priority 19) does not cancel them on same-site
   * subresources. Set for always-apply lists (except very large modifier lists
   * such as url-tracking) and for custom filters.
   */
  modifiers1p?: boolean;
  /**
   * Per-build random secret. When set, lines `!#trusted off <secret>` and
   * `!#trusted on <secret>` toggle trust for the following lines (tools wrap
   * untrusted sources of trusted lists in them). Any other `!#trusted` line is
   * ignored, so upstream text can never switch trust on.
   */
  trustSecret?: string;
}

/** A network rule plus the filters it came from (for transparency in the UI). */
export interface CompiledRule {
  rule: DnrRule;
  sources: string[];
  /** Total number of merged filters (sources may be truncated to 20). */
  sourceCount: number;
}

export interface SpecificCosmetic {
  /** 0 hide, 1 hide-exception, 2 procedural, 3 style, 4 flag, 5 procedural-exception — see CosmeticHostEntry. */
  kind: 0 | 1 | 2 | 3 | 4 | 5;
  /** Hostnames / entities ("google.*") this applies to. Never empty. */
  hosts: string[];
  /** Hosts excluded via ~host (only for kind 0/2/3). */
  excludedHosts: string[];
  /** CSS selector (kind 0/1), JSON ProceduralFilter (2), CSS rule text (3), flag name (4), raw procedural selector (5). */
  payload: string;
  raw: string;
}

export interface GenericCosmetic {
  selector: string;
  /** "#id" / ".class" key when the selector is keyed (lowly generic); null = highly generic. */
  token: string | null;
  /** ~host exclusions (filter like `~example.com##.ad`). */
  excludedHosts: string[];
  raw: string;
}

export interface ScriptletFilter {
  /** Canonical scriptlet name ("set-constant.js"); "" for the broad `#@#+js()` exception. */
  name: string;
  world: 'MAIN' | 'ISOLATED';
  args: string[];
  hosts: string[];
  excludedHosts: string[];
  exception: boolean;
  raw: string;
}

export interface CompiledList {
  listId: string;
  /** Plain DNR rules (urlFilter/domain based), merged and minimized, without ids. */
  rules: CompiledRule[];
  /** regexFilter rules (kept separate: own ruleset / runtime validation). */
  regexRules: CompiledRule[];
  specific: SpecificCosmetic[];
  generic: GenericCosmetic[];
  /** `#@#selector` without hostname: removes a generic selector everywhere (applied at build). */
  genericExceptions: string[];
  scriptlets: ScriptletFilter[];
  /** Hosts with $generichide / $elemhide / $specifichide exception filters. */
  generichideHosts: string[];
  specifichideHosts: string[];
  /** Redirect resource paths actually used (for web_accessible_resources). */
  usedRedirectResources: string[];
  stats: CompileStats;
}

export interface CompileStats {
  lines: number;
  filters: number;
  network: number;
  cosmetic: number;
  scriptlets: number;
  /** Filters we cannot express in MV3/DNR (or deliberately skip). */
  unsupported: number;
  /** Filters cancelled by $badfilter. */
  badfiltered: number;
  /** Samples: { line, reason }. */
  rejected: { filter: string; reason: string }[];
  /** reason -> count, for the build report. */
  reasons: Record<string, number>;
}

/** Result of compiling user/admin custom filters at runtime. */
export interface CompiledCustom {
  rules: DnrRule[];
  specific: SpecificCosmetic[];
  generic: GenericCosmetic[];
  scriptletsIgnored: number;
  errors: { line: number; text: string; reason: string }[];
}
