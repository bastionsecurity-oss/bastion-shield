# UI Optimised: implementation plan

Design source: Paper file «Bastion GmbH», page «Bastion Shield UI
Optimised». Start with the artboard «INDEX» and «00 — Grundlagen &
Komponenten». Rules: `DESIGN.md` (tokens, components, do's and don'ts) and
`AGENTS.md` (Vercel Web Interface Guidelines, Effective UI Design, Google
DESIGN.md).

Status (2026-10-22): phases 0 to 5 are implemented. Tests: `test/ui/i18n-keys.test.ts`
(missing keys, «·», three dots), unit tests per phase, e2e specs 21–26
(notices, pages, popup, shared palette/welcome, dashboard A and B).
Open product decisions are listed at the end of this file.

## Phase 0: foundations (prepared)

- `src/ui/shared/tokens.css`: new tokens `--danger`, `--danger-soft`,
  `--danger-soft-hover`, spacing `--space-1…--space-12`, `--radius-field`
  (12), `--radius-card` (24), `--control-h` (40), `--control-h-popup` (44),
  plus `.btn--outline`, `.btn--quiet`, `.btn--danger`, `.btn[aria-busy]`
  spinner, `.hit` (invisible hit area), `.trunc` and `.code-field`. The old
  classes stay so nothing changes until a view adopts the new ones.
- `src/ui/shared/text.ts`: `truncateMiddle(host, max)` (keeps start and
  registrable domain), `withUnit(value, unit)` (non-breaking space),
  `markInvisible(text)` (shows U+200B…U+200F, U+202A…U+202E, U+2066…U+2069
  as ⟨U+…⟩). Tests: `test/ui/ui-text.test.ts`.
- Red rule changed: Bundesrot stays for the logo and «Cyber-Vorfall?»; the
  muted danger red is allowed for destructive actions and errors.

- No middle dot «·» as a separator in UI text; use a spaced hyphen. Still
  in the code: 2 strings per locale in `_locales/*/messages.json`, plus
  `ui/dashboard/views/lab.ts` and `ui/popup/nerd.ts`. Replace them when the
  view is reworked.
- Dark dividers: `--line` is now 7 % white (was 11 %), `--line-soft` 5 %.

Decided in phase 0 (design default applied):
- Sentences and UI text 14px (`--text-md`), meta 12px, 13px only for
  disclosure and link labels where the artboards use it.
- Custom filter limit 1 MB (1'000'000 characters) in `views/filters.ts` and
  `background/store.ts`; a unit test keeps them equal (`cfTooLarge`).

## Phase 1: in-page notices (N01–N09)

File: `src/content/notice.ts` (own CSS in the closed shadow root, English
fallbacks). Changes:
- Card radius 24, padding 12, inner radius 12; tile 48 (`aria-hidden`), title
  17px, one sentence 14px, close button 32px, disclosure with
  `aria-expanded` and a 32px hit area.
- ClickFix: command collapsed by default («Befehl ansehen»), field max 6
  lines, `overflow-wrap: anywhere`, `overscroll-behavior: contain`, fade and
  character count only when it scrolls, `markInvisible()`.
- Lookalike: rows «Echt / Diese Seite», differing characters highlighted by a
  box (not colour), `truncateMiddle()` + «Ganze Adresse» disclosure.
- Stack (N05): newest on top, older ones collapse into «2 weitere Meldungen».
- `translate="no"` on domains, command and brand.
- New strings: `noticeClipTitle`, `noticeClipBody`, `noticeShowCommand`,
  `noticeHideCommand`, `noticeCopyHint`, `noticeChars`, `noticeLookTitle`,
  `noticeLookReal`, `noticeLookThis`, `noticeStay`, `noticeMore`
  (de/en/fr/it; copy in Paper «Iteration — Texte DE / FR / IT / EN»).

## Phase 2: extension pages (S01–S10)

Files: `src/pages/blocked.{html,css,ts}`, `src/pages/bounce.{html,css,ts}`.
- Tile 80, title «Gefährliche Seite blockiert», host chip (max 2 lines, then
  middle ellipsis), «Zurück» primary, «Trotzdem öffnen…» quiet, «Details»
  disclosure with reason, list and full URL (`overflow-wrap: anywhere`).
- Confirm bar «Nur in diesem Tab öffnen?»: focus starts on «Abbrechen»,
  «Seite öffnen» uses `.btn--danger`. Error row with «Erneut versuchen».
- `<meta name="theme-color">` for light and dark.
- Bounce: three short states with tile + one line.

## Phase 3: toolbar popup (P01–P15)

Files: `src/ui/popup/popup.{html,css,ts}`, `report.ts`, `state.ts`,
`site-set.ts`, `nerd.ts`.
- Buttons 44px, focus order: protection, mode, report, settings, CTA.
- Long host: `truncateMiddle()` in the protection tile, full host in `title`.
- Counts through `Intl.NumberFormat` and `withUnit()`; badge keeps «9k+».
- Reload bar does not cover the CTA (popup gets bottom padding while shown).
- States: «Hier nicht aktiv», «Schutz pausiert», «Keine Verbindung» with
  «Erneut versuchen» (new: re-run the state request, loading state).
- Report becomes a bottom sheet with «Was geteilt wird» as a key/value
  disclosure; GitHub and e-mail variants; inline error with retry.
- Nerd status line: lookalike explanation inline instead of a tooltip.

## Phase 4: dialogs, toasts, palette, welcome (D01–D08, T01, K01–K03, W01–W03)

Files: `src/ui/shared/controls.ts` (confirmDialog / choiceDialog), `dom.ts`
(toast), `tokens.css`, `src/ui/dashboard/palette.ts`, `views/welcome.ts`.
- Dialog: 440px, radius 24, primary first, buttons name the outcome,
  destructive with `.btn--danger`, focus on the safe action, narrow screens
  stack buttons full width.
- «Alles zurücksetzen» needs a checkbox before the button enables.
- Toast: max 420px, 3 stacked, polite live region; new action slot for
  «Rückgängig» (6 s) and «Erneut versuchen».
- Reversible actions switch from confirm to undo toast: remove list, remove
  site exception.
- Palette: empty state with a suggestion, long labels truncated, match
  highlight in bold (no colour).

## Phase 5: dashboard (DB01–DB43)

Files: `src/ui/dashboard/dashboard.{html,css,ts}`, `panel.html`, `rail.ts`,
`views/*.ts`.
- One rail spec for tab (240) and panel (200): brand, search, groups
  Überblick / Regeln / System, CTA at the bottom.
- Every view: empty, dense (search, «Ältere laden», middle-truncated hosts),
  error banner with retry, locked rows with lock + «Von Ihrer Organisation
  festgelegt», dark.
- Eigene Filter: dirty bar «3 Änderungen nicht angewendet» with «Verwerfen»
  and «Filter anwenden», invalid lines flagged with line number and reason.
- Website-Ausnahmen: counter «3 von 1'248», limits (10'000 sites, 253
  characters per host) shown before they are hit.
- Meine Listen: upload validation (type, size, empty, duplicate URL), name
  counter at 120.
- New behaviour (needs product decision): rename a list, «Filter
  zurücksetzen», «Alle 8 anzeigen» in the overview top lists.

## Acceptance checklist (every screen)

Vercel Web Interface Guidelines
- [ ] Keyboard only works; focus visible and never covered; dialogs trap
      and restore focus.
- [ ] Targets ≥ 24px (links in cards 32px, popup 44px).
- [ ] Loading buttons keep their label; spinner delayed, minimum duration.
- [ ] Labels opening a further step end with «…»; single «…» character.
- [ ] Destructive: confirm with outcome-named buttons, or undo toast.
- [ ] `aria-live` for toasts and validation, `role="alert"` for notices.
- [ ] Icons `aria-hidden`, icon buttons `aria-label`.
- [ ] Short, average and very long content tested; no overflow.
- [ ] Numbers via `Intl.NumberFormat`, nbsp before units and in key combos.
- [ ] `translate="no"` on domains, commands, keys, brand.
- [ ] `prefers-reduced-motion` honoured; no `transition: all`.
- [ ] Hover, pressed, focus have more contrast than rest.
- [ ] `color-scheme` and `theme-color` set on pages.

Google DESIGN.md
- [ ] Only tokens from `DESIGN.md` / `tokens.css`; no literal colours in
      views.
- [ ] `npx @google/design.md lint DESIGN.md` has no errors and no
      contrast warnings.
- [ ] Components match the `components:` entries (button heights, radii,
      tile sizes, notice card, dialog, toast).
- [ ] Do's and Don'ts respected (Bundesrot, danger red, tooltips, one
      sentence).

Effective UI Design
- [ ] One primary per view, primary first.
- [ ] Quiet buttons underlined, secondary outlined (≥ 3:1).
- [ ] Text ≥ 4.5:1, UI ≥ 3:1; sentences 14px, meta ≥ 12px.
- [ ] Spacing on the 4/8 scale.

## Open product decisions

- Blocking mode name: the popup artboards say «Streng», the dashboard
  artboards «Aggressiv». The code keeps «Aggressiv» (`modeAggressive`).
- «Filter zurücksetzen» is not built (no artboard). «IT kontaktieren» shows
  only when the policy sets `supportUrl` or `supportEmail`.
- Settings keep three rows DB28 leaves out («So gehts», links to filter
  history, fingerprinting counter).
- Undo of a removed list keeps the copy in service-worker memory; if the
  worker restarts within the 6 s, «Rückgängig» fails with a retry toast.
