// Bastion Shield — the nerd mode easter egg: when nerd mode is switched on,
// the settings it unlocks (fingerprinting counter, lookalike domains,
// protected domains) and the «Entwicklertools» navigation entry decode in
// place out of cipher glyphs, briefly in terminal green, then settle back to
// the normal look. No overlay: the real UI does the trick, and it only runs
// on the switch, never on page load.
//
// Purely decorative: the text is set back verbatim when done, the elements
// keep their accessible names throughout (aria-label while scrambling), and
// with reduced motion nothing animates.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { reducedMotion } from '../shared/dom.ts';

// Half-width katakana: about as wide as Latin letters, so lines barely jump while they decode.
const GLYPHS = '0123456789ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ<>/{}[]*+#$%&=?!';
const SCRAMBLE_MS = 45; // a glyph holds this long, so the noise stays readable as noise

function glyph(): string {
  return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
}

/**
 * Decode the element's own text: every character scrambles until its
 * reveal time, revealed roughly left to right with some jitter. Only elements
 * whose content is plain text are touched (children would be lost).
 */
function decode(el: HTMLElement, delay: number, duration: number): Promise<void> {
  const text = el.textContent ?? '';
  if (!text.trim() || el.children.length > 0 || el.dataset.decoding !== undefined) return Promise.resolve();
  const chars = [...text];
  const reveal = chars.map((_, i) => delay + (i / Math.max(1, chars.length - 1)) * duration * 0.7 + Math.random() * duration * 0.3);
  const end = delay + duration;
  const noise = chars.map((c) => (/\s/.test(c) ? c : glyph()));
  const hadLabel = el.hasAttribute('aria-label');
  if (!hadLabel) el.setAttribute('aria-label', text);
  // Glyphs are a little wider than the text: hold the height so nothing below jumps.
  const height = el.offsetHeight;
  if (height) {
    el.style.height = `${height}px`;
    el.style.overflow = 'hidden';
  }
  el.dataset.decoding = '';
  el.classList.add('nerd-decode');
  el.textContent = noise.join('');
  let start = 0;
  let lastSwap = 0;
  return new Promise((resolve) => {
    const done = () => {
      el.textContent = text;
      el.style.removeProperty('height');
      el.style.removeProperty('overflow');
      if (!hadLabel) el.removeAttribute('aria-label');
      delete el.dataset.decoding;
      // Hold the green a moment, then fade back to the normal colour (CSS transition).
      setTimeout(() => el.classList.add('nerd-decode--settle'), 260);
      setTimeout(() => el.classList.remove('nerd-decode', 'nerd-decode--settle'), 1100);
      resolve();
    };
    const frame = (now: number) => {
      if (!el.isConnected) return done();
      if (!start) start = now;
      const elapsed = now - start;
      if (elapsed >= end) return done();
      if (now - lastSwap > SCRAMBLE_MS) {
        for (let i = 0; i < noise.length; i++) if (!/\s/.test(chars[i])) noise[i] = glyph();
        lastSwap = now;
      }
      el.textContent = chars.map((c, i) => (elapsed >= reveal[i] ? c : noise[i])).join('');
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
}

/** Text inside `root` that nerd mode unlocks: setting labels and short hints. */
const TARGETS = '.db-row__label, .nerd-domains__hint, .nerd-domains__policy-head > span:first-child, .nerd-help__body dt, .nerd-help__body dd, .nerd-help__lead > span';

/**
 * Decode the given elements (or the decodable text inside them) one after
 * another, top to bottom. Rows also slide in.
 */
export function revealNerd(...roots: (Element | null | undefined)[]): void {
  if (reducedMotion() || document.visibilityState === 'hidden') return;
  const els: HTMLElement[] = [];
  for (const root of roots) {
    if (!root) continue;
    if (root.matches('.db-nav__label, ' + TARGETS)) els.push(root as HTMLElement);
    else els.push(...Array.from(root.querySelectorAll<HTMLElement>(TARGETS)));
  }
  // Text in a closed <details> decodes when it is opened, not now.
  const shown = els.filter((el) => !el.closest('details:not([open]) > :not(summary)'));
  shown.forEach((el, i) => {
    const row = el.closest<HTMLElement>('.db-row, .nerd-domains__block');
    if (row && !row.classList.contains('nerd-rise')) {
      row.style.setProperty('--d', `${i * (shown.length > 10 ? 35 : 90)}ms`);
      row.classList.add('nerd-rise');
      row.addEventListener('animationend', () => row.classList.remove('nerd-rise'), { once: true });
    }
    // Long hints decode a little longer, but never drag; long lists stagger faster.
    const len = (el.textContent ?? '').length;
    const step = shown.length > 10 ? 35 : 90;
    void decode(el, i * step, Math.min(900, 380 + len * 9));
  });
}
