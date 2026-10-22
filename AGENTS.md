# AGENTS.md

Rules for coding agents (and people) working on the Bastion Shield UI.
Read `DESIGN.md` first: it holds the tokens, components and do's and
don'ts. `docs/UI-OPTIMISED.md` maps the Paper designs to the code.

## Commands

- `npm run build` builds `dist/`, `npm run typecheck` runs tsc.
- `npm test` runs the unit tests, `npm run test:e2e` the Playwright tests.
- `npx @google/design.md lint DESIGN.md` checks DESIGN.md (contrast, refs).

## Where the UI lives

- Tokens and shared controls: `src/ui/shared/tokens.css`, `controls.ts`,
  `dom.ts`, `icons.ts`, `i18n.ts`.
- Toolbar popup: `src/ui/popup/` (360px). Expanded popup and dashboard:
  `src/ui/dashboard/` (`panel.html` 760×560, `dashboard.html` tab).
- In-page notices: `src/content/notice.ts` (closed shadow root, own CSS,
  English fallbacks). Extension pages: `src/pages/` (blocked, bounce).
- Strings: `src/_locales/{de,en,fr,it}/messages.json`. Every new string goes
  into all four files in the same change.

## Rules

These follow the Vercel Web Interface Guidelines, Effective UI Design and
Google DESIGN.md. They are checked in review.

### Copy
- Swiss German: «ss», «Guillemets», formal «Sie». Sentence case.
- A title says what happened, one sentence says what to do. Details go
  behind a disclosure, not into a tooltip.
- Buttons are verb + noun and name the outcome («Verlauf löschen»,
  «Verlauf behalten»). A label that opens a further step ends with «…».
- Numbers via `Intl.NumberFormat(<lang>-CH)`; non-breaking space between a
  number and its unit and inside key combos (`Ctrl K`).
- Use the single ellipsis character «…», never three dots.
- Never use the middle dot «·» as a separator in UI text. Separate parts with
  a spaced hyphen: «1'204 Zeilen - 38 KB von 1 MB», «20min.ch - Skript».
  Existing strings with «·» (for example the palette footer) change when
  their view is reworked.

### Interaction and accessibility
- Every flow works with the keyboard. Focus is always visible (2px
  `--focus`, 2px offset) and never hidden behind overlays.
- Dialogs and sheets trap focus, start on the safe action and return focus
  to the trigger. `overscroll-behavior: contain` inside them and inside
  scrolling fields.
- Hit targets: at least 24px, 32px for links in cards, 44px in the popup.
  Extend small icons with an invisible hit area.
- Icon-only buttons get an `aria-label`. Decorative tiles and icons get
  `aria-hidden="true"`. Prefer native elements over ARIA.
- Async feedback (toasts, inline validation) uses `aria-live="polite"`;
  security notices use `role="alert"`.
- Loading buttons keep their label and show a spinner after ~150ms, for at
  least ~300ms.
- Reversible actions: toast with «Rückgängig». Irreversible: confirm dialog
  with outcome-named buttons; heavy ones need an extra checkbox.
- Never block paste, never disable zoom.
- Mark domains, commands, keys and «Bastion Shield» with `translate="no"`.

### Layout and content
- Spacing 4, 8, 12, 16, 24, 32, 48; radii 12 / 24 / pill, concentric.
- Every screen handles empty, dense, very long, error, loading, locked (by
  organisation) and dark states.
- Text never overflows its box: hosts are cut in the middle (keep start and
  TLD), names at the end, commands wrap with `overflow-wrap: anywhere` and
  scroll after 6 lines. Full values stay reachable (disclosure or `title`).
- Inputs show a counter from 80 % of their limit and the error right below
  the field, naming the fix.

### Visual
- Contrast: text ≥ 4.5:1, control boundaries ≥ 3:1 (use `--line-strong`).
- Hover, pressed and focus have more contrast than rest.
- Colour never carries status alone; pair it with an icon and text.
- Bundesrot only for the logo diamond and «Cyber-Vorfall?». The muted
  danger red is for destructive actions and errors only.
- Floating surfaces: 1px line + two shadow layers. Dark mode via tokens,
  `color-scheme: light dark` and `theme-color` on pages.

### Motion
- Honour `prefers-reduced-motion`. Animate `transform` and `opacity` only,
  list properties explicitly, never `transition: all`.
- Motion explains cause and effect (open, expand, confirm); nothing loops.
