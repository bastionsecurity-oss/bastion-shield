// Bastion Shield — procedural filtering entry (dist/content/procedural.js).
//
// Not registered: the service worker injects it with scripting.executeScript
// into the ISOLATED world of a frame that asked for it (`cosmetic:procedural`,
// ARCHITECTURE §5.2.5), so pages without procedural filters never pay for it.
// It exposes self.bastionProcedural.apply(filters) and immediately applies
// filters content/cosmetic.js parked in self.bastionProceduralPending.
// Injecting it twice is harmless.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ProceduralFilter } from '../shared/types.ts';
import { isolatedGlobals } from './api.ts';
import { ProceduralFilterer } from './procedural-engine.ts';

function install(): void {
  const g = isolatedGlobals();
  if (g.bastionProcedural === undefined) {
    let filterer: ProceduralFilterer | null = null;
    g.bastionProcedural = {
      apply(filters: ProceduralFilter[]): void {
        try {
          if (filterer === null) filterer = new ProceduralFilterer(document);
          filterer.apply(filters);
        } catch {
          // never surface engine errors in the page console
        }
      },
    };
  }
  const pending = g.bastionProceduralPending;
  if (pending !== undefined) {
    g.bastionProceduralPending = undefined;
    g.bastionProcedural.apply(pending);
  }
}

try {
  install();
} catch {
  // ignore
}
