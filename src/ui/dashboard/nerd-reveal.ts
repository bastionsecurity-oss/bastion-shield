// Bastion Shield — the nerd mode easter egg: when nerd mode is switched on,
// the settings it unlocks (fingerprinting counter, lookalike domains,
// protected domains) and the «Entwicklertools» navigation entry assemble in
// place out of swirling text glyphs, the same glyphs and spring the name in
// the website footer is made of. No overlay panel: the real UI does the
// trick, and it only runs on the switch, never on page load.
//
// Every character gets a glyph on a page-wide canvas that drifts around its
// slot, is released roughly left to right and springs home, where it turns
// into the real character. The text itself stays in the DOM (only painted
// transparent meanwhile), so accessible names and layout never change. With
// reduced motion nothing animates.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { reducedMotion } from '../shared/dom.ts';

// The website footer's glyph set, so the brand speaks one visual language.
const GLYPHS = '|^$#@*~:.';
const GLYPH_MS = 90; // a glyph holds this long before it cycles, as in the footer
const SPRING = 60; // home spring once released (footer value)
const DRIFT = 7; // weak spring while drifting, so glyphs orbit instead of landing
const DAMP = 0.86; // velocity kept per 60 Hz frame (footer value)
const GIVE_UP_MS = 1200; // after release a glyph lands by then at the latest

interface Char {
  ch: string;
  x: number; // left edge, relative to the element's box
  base: number; // baseline, relative to the element's box
  cx: number; // centre, relative to the element's box
  cy: number;
  ox: number; // offset from home and velocity
  oy: number;
  vx: number;
  vy: number;
  r0: number; // starting distance, for the fade-in
  g: number;
  release: number;
  landed: boolean;
}

interface Job {
  el: HTMLElement;
  font: string;
  glyphFont: string;
  color: string;
  chars: Char[];
  start: number;
  doneAt: number;
}

const jobs: Job[] = [];
let canvas: HTMLCanvasElement | null = null;
let ctx: CanvasRenderingContext2D | null = null;
let raf = 0;
let last = 0;
let glyphColor = '';
let monoFamily = '';

function ensureCanvas(): CanvasRenderingContext2D | null {
  if (ctx && canvas?.isConnected) return ctx;
  canvas = document.createElement('canvas');
  canvas.className = 'nerd-field';
  canvas.setAttribute('aria-hidden', 'true');
  document.body.append(canvas);
  ctx = canvas.getContext('2d');
  const root = getComputedStyle(document.documentElement);
  glyphColor = root.getPropertyValue('--text-2').trim() || 'gray';
  monoFamily = root.getPropertyValue('--font-mono').trim() || 'monospace';
  return ctx;
}

function fitCanvas(c: HTMLCanvasElement, g: CanvasRenderingContext2D): void {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.round(innerWidth * dpr);
  const h = Math.round(innerHeight * dpr);
  if (c.width !== w || c.height !== h) {
    c.width = w;
    c.height = h;
  }
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
}

/**
 * Lay out the element's characters and start their glyphs around their
 * slots. Only elements whose content is plain text are touched.
 */
function prepare(el: HTMLElement, delay: number, duration: number, now: number): Job | null {
  const text = el.textContent ?? '';
  if (!text.trim() || el.children.length > 0 || el.dataset.decoding !== undefined) return null;
  const g = ensureCanvas();
  if (!g) return null;
  const cs = getComputedStyle(el);
  const font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
  const size = parseFloat(cs.fontSize) || 14;
  const box = el.getBoundingClientRect();
  const range = document.createRange();
  g.font = font;
  const chars: Char[] = [];
  for (const node of Array.from(el.childNodes)) {
    if (node.nodeType !== Node.TEXT_NODE) continue;
    const s = node.nodeValue ?? '';
    for (let i = 0; i < s.length; ) {
      const ch = String.fromCodePoint(s.codePointAt(i) ?? 32);
      range.setStart(node, i);
      range.setEnd(node, i + ch.length);
      i += ch.length;
      if (/\s/.test(ch)) continue;
      const r = range.getClientRects()[0];
      if (!r) continue;
      const m = g.measureText(ch);
      const asc = m.fontBoundingBoxAscent || size * 0.8;
      const desc = m.fontBoundingBoxDescent || size * 0.2;
      // Start somewhere on a flat ring around the slot, already circling it.
      const a = Math.random() * Math.PI * 2;
      const dist = size * (1.4 + Math.random() * 2.2);
      const spin = (Math.random() < 0.5 ? -1 : 1) * dist * (2 + Math.random() * 2);
      chars.push({
        ch,
        x: r.left - box.left,
        base: r.top - box.top + (r.height - asc - desc) / 2 + asc,
        cx: r.left - box.left + r.width / 2,
        cy: r.top - box.top + r.height / 2,
        ox: Math.cos(a) * dist,
        oy: Math.sin(a) * dist * 0.6,
        vx: -Math.sin(a) * spin,
        vy: Math.cos(a) * spin * 0.6,
        r0: dist,
        g: (Math.random() * GLYPHS.length) | 0,
        release: 0,
        landed: false,
      });
    }
  }
  if (!chars.length) return null;
  // Released roughly left to right, with some jitter.
  chars.forEach((c, i) => {
    c.release = delay + (i / Math.max(1, chars.length - 1)) * duration * 0.7 + Math.random() * duration * 0.3;
  });
  // Read the colour before .nerd-decode paints it transparent (the style object is live).
  const job: Job = { el, font, glyphFont: `500 ${Math.round(size)}px ${monoFamily}`, color: cs.color, chars, start: now, doneAt: 0 };
  el.dataset.decoding = '';
  el.classList.add('nerd-decode');
  return job;
}

function finish(job: Job): void {
  job.el.classList.remove('nerd-decode');
  delete job.el.dataset.decoding;
}

function frame(now: number): void {
  raf = 0;
  const g = ctx;
  if (!g || !canvas) return;
  const dt = Math.min(0.033, (now - (last || now)) / 1000);
  last = now;
  fitCanvas(canvas, g);
  g.clearRect(0, 0, innerWidth, innerHeight);
  const damp = Math.pow(DAMP, dt * 60);
  const tick = Math.floor(now / GLYPH_MS);
  for (let j = jobs.length - 1; j >= 0; j--) {
    const job = jobs[j];
    // Once every glyph landed, hand the text back to the DOM a frame later.
    if (!job.el.isConnected || (job.doneAt && now - job.doneAt > 80)) {
      finish(job);
      jobs.splice(j, 1);
      continue;
    }
    const t = now - job.start;
    const box = job.el.getBoundingClientRect();
    let flying = 0;
    for (const c of job.chars) {
      if (!c.landed) {
        const released = t >= c.release;
        const k = released ? SPRING : DRIFT;
        c.vx = (c.vx - c.ox * k * dt) * damp;
        c.vy = (c.vy - c.oy * k * dt) * damp;
        c.ox += c.vx * dt * (released ? 6 : 1);
        c.oy += c.vy * dt * (released ? 6 : 1);
        if (released && ((Math.hypot(c.ox, c.oy) < 0.6 && Math.hypot(c.vx, c.vy) < 6) || t - c.release > GIVE_UP_MS)) c.landed = true;
      }
      if (c.landed) {
        g.globalAlpha = 1;
        g.font = job.font;
        g.fillStyle = job.color;
        g.textAlign = 'left';
        g.textBaseline = 'alphabetic';
        g.fillText(c.ch, box.left + c.x, box.top + c.base);
        continue;
      }
      flying++;
      // Closer to home reads stronger, like the footer glyphs near the pointer.
      const near = Math.max(0, 1 - Math.hypot(c.ox, c.oy) / c.r0);
      g.globalAlpha = 0.35 + near * 0.65;
      g.font = job.glyphFont;
      g.fillStyle = glyphColor;
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillText(GLYPHS[(c.g + tick) % GLYPHS.length], box.left + c.cx + c.ox, box.top + c.cy + c.oy);
    }
    if (!flying && !job.doneAt) job.doneAt = now;
  }
  g.globalAlpha = 1;
  if (jobs.length) {
    raf = requestAnimationFrame(frame);
  } else {
    canvas.remove();
    canvas = null;
    ctx = null;
    last = 0;
  }
}

/** Text inside `root` that nerd mode unlocks: setting labels and short hints. */
const TARGETS = '.db-row__label, .nerd-domains__hint, .nerd-domains__policy-head > span:first-child, .nerd-help__body dt, .nerd-help__body dd, .nerd-help__lead > span';

/**
 * Assemble the given elements (or the text inside them) one after another,
 * top to bottom. Rows also slide in.
 */
export function revealNerd(...roots: (Element | null | undefined)[]): void {
  if (reducedMotion() || document.visibilityState === 'hidden') return;
  const els: HTMLElement[] = [];
  for (const root of roots) {
    if (!root) continue;
    if (root.matches('.db-nav__label, ' + TARGETS)) els.push(root as HTMLElement);
    else els.push(...Array.from(root.querySelectorAll<HTMLElement>(TARGETS)));
  }
  // Text in a closed <details> assembles when it is opened, not now.
  const shown = els.filter((el) => !el.closest('details:not([open]) > :not(summary)'));
  const now = performance.now();
  // Long lists stagger faster.
  const step = shown.length > 10 ? 35 : 90;
  shown.forEach((el, i) => {
    const row = el.closest<HTMLElement>('.db-row, .nerd-domains__block');
    if (row && !row.classList.contains('nerd-rise')) {
      row.style.setProperty('--d', `${i * step}ms`);
      row.classList.add('nerd-rise');
      row.addEventListener('animationend', () => row.classList.remove('nerd-rise'), { once: true });
    }
    // Long hints take a little longer, but never drag.
    const len = (el.textContent ?? '').length;
    const job = prepare(el, i * step, Math.min(900, 380 + len * 9), now);
    if (job) jobs.push(job);
  });
  if (jobs.length && !raf) raf = requestAnimationFrame(frame);
}
