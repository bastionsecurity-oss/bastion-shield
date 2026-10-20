// Bastion Shield — helpers shared by the nerd mode MAIN-world scripts
// (clipguard.ts, fpmeter.ts): the event channel to the ISOLATED relay and
// the "already patched" probe. Built-ins are captured when the bundle loads,
// before any page script runs (document_start).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { nerdEventName, nerdSentinel } from './nerd-channel.ts';
import type { Stealth } from './stealth.ts';
import { createStealth, findAncestorMask, ownStackNeedle } from './stealth.ts';

const RApply = Reflect.apply;
const ObjCreate = Object.create;
const ObjGetDesc = Object.getOwnPropertyDescriptor;
const FnProto = Function.prototype;
const dispatch = EventTarget.prototype.dispatchEvent;
const CustomEventCtor = typeof CustomEvent === 'function' ? CustomEvent : undefined;

export interface NerdMain {
  /** Extension origin as seen in our stack frames. */
  origin: string;
  stealth: Stealth;
  /** Send a detail string to the relay; true when the relay cancelled the event (block). Never throws. */
  send(detail: string): boolean;
  /** Install the Function.prototype.toString mask (call after patching). */
  finish(): void;
}

/**
 * True when the realm's current Function.prototype.toString answers the
 * sentinel, i.e. a copy of the same script already patched this realm.
 * (Unlike a comparison with a captured toString, this also works when the
 * first copy's proxy is what this copy captured.)
 */
function realmAnswers(sentinel: string, reply: string): boolean {
  try {
    const d = ObjGetDesc(FnProto, 'toString');
    if (d === undefined || typeof d.value !== 'function') return false;
    return RApply(d.value, sentinel, []) === reply;
  } catch {
    return false;
  }
}

/** Set up a MAIN-world nerd script, or null when this realm already runs it (or cannot). */
export function setupNerdMain(script: string): NerdMain | null {
  if (typeof window === 'undefined' || typeof document === 'undefined' || CustomEventCtor === undefined) return null;
  const origin = ownStackNeedle();
  const { sentinel, reply } = nerdSentinel(origin, script);
  if (realmAnswers(sentinel, reply)) return null;
  const stealth = createStealth(origin, sentinel, reply);
  const name = nerdEventName(origin);
  const win = window;
  return {
    origin,
    stealth,
    send(detail: string): boolean {
      try {
        // Null-prototype init dictionary: the WebIDL conversion must not see page-defined Object.prototype getters.
        const init = ObjCreate(null) as CustomEventInit<string>;
        init.detail = detail;
        init.cancelable = true;
        const ev = new CustomEventCtor(name, init);
        return RApply(dispatch, win, [ev]) === false;
      } catch {
        return false;
      }
    },
    finish(): void {
      stealth.installToString(findAncestorMask(win, sentinel, reply));
    },
  };
}
