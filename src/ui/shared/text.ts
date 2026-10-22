// Bastion Shield — text helpers that keep long content inside its box
// (DESIGN.md «Layout»): hosts cut in the middle, numbers glued to their unit,
// invisible control characters made visible in blocked commands.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const ELLIPSIS = '…';
const NBSP = ' ';

/**
 * Shortens a host name in the middle so its start and the registrable part at
 * the end stay readable: "secure-login-ubs.ch-verify.top" -> "secure-l…ch-verify.top".
 * The tail is the last two labels; when that alone is too long the cut falls
 * evenly between start and end. Show the full host elsewhere (title, disclosure).
 */
export function truncateMiddle(host: string, max: number): string {
  if (max < 3 || host.length <= max) return host;
  const labels = host.split('.');
  const tail = labels.length > 2 ? labels.slice(-2).join('.') : '';
  const room = max - 1;
  if (tail && tail.length <= room - 4) {
    return host.slice(0, room - tail.length) + ELLIPSIS + tail;
  }
  const head = Math.ceil(room / 2);
  return host.slice(0, head) + ELLIPSIS + host.slice(host.length - (room - head));
}

/** "612 Zeichen", "1.2 MB": a non-breaking space so number and unit never wrap apart. */
export function withUnit(value: string | number, unit: string): string {
  return `${value}${NBSP}${unit}`;
}

// Zero-width and bidi control characters that can hide part of a command.
const INVISIBLE = /[​-‏‪-‮⁦-⁩]/g;

/** Replaces invisible and bidi control characters with a visible ⟨U+XXXX⟩ marker. */
export function markInvisible(text: string): string {
  return text.replace(INVISIBLE, (ch) => `⟨U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}

/** True when markInvisible() would change the text. */
export function hasInvisible(text: string): boolean {
  INVISIBLE.lastIndex = 0;
  return INVISIBLE.test(text);
}
