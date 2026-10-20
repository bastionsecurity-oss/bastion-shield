// Bastion Shield — counters of the current page load, shared by the compact
// popup and the expanded view («Diese Website»): the identity of an event
// (backlog, live stream and state snapshots repeat events), the counter it
// moves, and the savings sample (types of requests that never loaded).
// DOM-free.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { savesRequest } from '../../shared/constants.ts';
import type { ActivityEvent, PopupState } from '../../shared/types.ts';

export type PageCounts = PopupState['counts'];

/** Typed events kept for the savings estimate (estimateFromSample scales it up). */
export const SAMPLE_MAX = 400;

/** Identity of an event across the backlog, the live stream and a popup:state snapshot. */
export function eventKey(e: ActivityEvent): string {
  return `${e.t}|${e.kind}|${e.frameId}|${e.url}`;
}

/** Count `e` into `counts`; third-party hosts once each when `thirdHosts` tracks them. */
export function countEvent(counts: PageCounts, e: ActivityEvent, thirdHosts?: Set<string>): void {
  if (e.kind === 'blocked' || e.kind === 'strict') counts.blocked++;
  else if (e.kind === 'redirected') counts.redirected++;
  else if (e.kind === 'debounced') counts.debounced++;
  else if (e.kind === 'stripped') counts.stripped++;
  if (thirdHosts && e.thirdParty && e.host && !thirdHosts.has(e.host)) {
    thirdHosts.add(e.host);
    counts.thirdPartyHosts++;
  }
}

/** Add the type of `e` to the savings sample when its request never loaded. */
export function sampleType(types: string[], e: ActivityEvent): void {
  if (savesRequest(e.kind) && types.length < SAMPLE_MAX) types.push(e.type);
}
