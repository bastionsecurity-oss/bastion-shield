// Bastion Shield — the nerd mode easter egg: switching nerd mode on plays a
// short "access granted" sequence over the dashboard or the expanded popup.
// A CRT powers on, a shell prompt types itself, «NERD MODE» decodes out of
// cipher glyphs with a chromatic glitch, then the unlocked tools decode one
// by one and the screen powers off again. About four seconds; any key or
// click skips it. With reduced motion the text simply fades in and out.
//
// Purely decorative: the switch has already been saved when this runs, and
// a polite status message tells screen readers what happened.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { h, reducedMotion } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { shortcutLabel } from './rail.ts';

// Half-width katakana: about as wide as the monospace Latin, so the line does not jump while it decodes.
const GLYPHS = '0123456789ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ<>/{}[]*+#$%&=?!';
const SCRAMBLE_MS = 45; // a glyph holds this long, so the noise stays readable as noise

let playing: (() => void) | null = null;

function glyph(): string {
  return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
}

/**
 * Decode `text` into `el`: every character scrambles until its own reveal
 * time, revealed roughly left to right with some jitter. Resolves when done.
 */
function decode(el: HTMLElement, text: string, duration: number, signal: AbortSignal): Promise<void> {
  const chars = [...text];
  const reveal = chars.map((_, i) => (i / Math.max(1, chars.length - 1)) * duration * 0.7 + Math.random() * duration * 0.3);
  const noise = chars.map((c) => (c === ' ' ? ' ' : glyph()));
  let start = 0;
  let lastSwap = 0;
  return new Promise((resolve) => {
    const frame = (now: number) => {
      if (signal.aborted) return resolve();
      if (!start) start = now;
      const elapsed = now - start;
      if (now - lastSwap > SCRAMBLE_MS) {
        for (let i = 0; i < noise.length; i++) if (chars[i] !== ' ') noise[i] = glyph();
        lastSwap = now;
      }
      el.textContent = chars.map((c, i) => (elapsed >= reveal[i] ? c : noise[i])).join('');
      if (elapsed >= duration) {
        el.textContent = text;
        resolve();
        return;
      }
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
}

/** Type `text` into `el`, one character at a time. */
function type(el: HTMLElement, text: string, perChar: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    let i = 0;
    const step = () => {
      if (signal.aborted) return resolve();
      el.textContent = text.slice(0, ++i);
      if (i >= text.length) return resolve();
      setTimeout(step, perChar * (0.6 + Math.random() * 0.8));
    };
    step();
  });
}

function wait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const id = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => (clearTimeout(id), resolve()), { once: true });
  });
}

/** Play the sequence once. A second call while it runs is ignored. */
export function playNerdReveal(): void {
  if (playing || document.visibilityState === 'hidden') return;
  const reduced = reducedMotion();
  const ctl = new AbortController();
  const { signal } = ctl;

  const title = 'NERD MODE';
  const tools = [shortcutLabel('K'), 'bisect', 'why', 'blame', 'fp', 'lab'];

  const prompt = h('span', { class: 'nr__prompt-text' });
  const titleEl = h('span', { class: 'nr__title-text', text: reduced ? title : '' });
  const titleWrap = h('h2', { class: 'nr__title', attrs: { 'data-text': title } }, titleEl);
  const sub = h('p', { class: 'nr__sub', text: reduced ? t('nerdRevealSub') : '' });
  const chips = tools.map((x) => h('li', { class: 'nr__chip', text: reduced ? x : '' }));
  const overlay = h(
    'div',
    { class: `nr${reduced ? ' nr--still' : ''}` },
    h('span', { class: 'sr-only', text: t('nerdRevealSr'), attrs: { role: 'status' } }),
    h(
      'div',
      { class: 'nr__screen', attrs: { 'aria-hidden': 'true' } },
      h('p', { class: 'nr__prompt' }, h('span', { class: 'nr__ps1', text: '$' }), prompt, h('span', { class: 'nr__caret' })),
      titleWrap,
      sub,
      h('ul', { class: 'nr__chips' }, ...chips),
      h('p', { class: 'nr__skip', text: t('nerdRevealSkip') }),
    ),
    h('div', { class: 'nr__scan', attrs: { 'aria-hidden': 'true' } }),
  );

  const finish = () => {
    if (!playing) return;
    playing = null;
    ctl.abort();
    removeEventListener('keydown', onKey, true);
    overlay.classList.add('nr--out');
    const done = () => overlay.remove();
    overlay.addEventListener('animationend', (ev) => ev.target === overlay && done());
    setTimeout(done, 700); // in case animations are off
  };
  const onKey = (ev: KeyboardEvent) => {
    ev.preventDefault();
    ev.stopPropagation();
    finish();
  };
  playing = finish;
  overlay.addEventListener('click', finish);
  addEventListener('keydown', onKey, true);
  document.body.appendChild(overlay);

  if (reduced) {
    void wait(2200, signal).then(finish);
    return;
  }

  void (async () => {
    await wait(260, signal);
    await type(prompt, 'sudo bastion --nerd', 34, signal);
    await wait(180, signal);
    titleWrap.classList.add('nr__title--live');
    await decode(titleEl, title, 1150, signal);
    titleWrap.classList.add('nr__title--locked');
    await wait(120, signal);
    await decode(sub, t('nerdRevealSub'), 650, signal);
    for (const [i, chip] of chips.entries()) {
      chip.classList.add('nr__chip--on');
      void decode(chip, tools[i], 380, signal);
      await wait(110, signal);
    }
    await wait(1500, signal);
    finish();
  })();
}
