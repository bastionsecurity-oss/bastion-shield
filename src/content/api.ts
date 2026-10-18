// Bastion Shield — globals shared by the isolated-world content scripts.
// cosmetic.js (registered) and procedural.js (injected on demand by the SW)
// run in the same isolated world of a frame, so they meet on `self`. The page
// cannot see isolated-world globals.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ProceduralFilter } from '../shared/types.ts';

/** Exposed by content/procedural.js. */
export interface ProceduralApi {
  /** Add filters (deduplicated by `raw`) and evaluate them now and on DOM changes. */
  apply(filters: ProceduralFilter[]): void;
}

export interface IsolatedGlobals {
  bastionProcedural?: ProceduralApi;
  /**
   * Filters waiting for the engine: cosmetic.js parks them here before it
   * asks the SW to inject procedural.js, which consumes them on load. This
   * makes the hand-over independent of whether the SW answers before or
   * after executeScript has run.
   */
  bastionProceduralPending?: ProceduralFilter[];
  /** Set by cosmetic.js to make a duplicate injection a no-op. */
  bastionCosmeticLoaded?: boolean;
}

export function isolatedGlobals(): IsolatedGlobals {
  return self as unknown as IsolatedGlobals;
}
