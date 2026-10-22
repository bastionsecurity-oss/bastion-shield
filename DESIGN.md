---
version: alpha
name: Bastion Shield UI
description: Product UI of the Bastion Shield browser extension (popup, in-page notices, extension pages, dashboard). Gletscher palette, Inter / Inter Tight / IBM Plex Mono. Source of truth for tokens is src/ui/shared/tokens.css; this file mirrors it for people and coding agents.
colors:
  primary: "#171C1E"
  primary-hover: "#2A3134"
  primary-pressed: "#4C575D"
  on-primary: "#FFFFFF"
  surface: "#FFFFFF"
  ground: "#F2F4F5"
  surface-cool: "#E4E8E9"
  on-surface: "#171C1E"
  on-surface-2: "#4C575D"
  on-surface-3: "#5F6B71"
  line: "#D7DDDF"
  line-strong: "#798186"
  focus: "#2A3134"
  danger: "#A3231A"
  danger-pressed: "#8A1D15"
  danger-container: "#FBEAE8"
  danger-container-hover: "#F6D6D2"
  brand-red: "#DA291C"
  brand-red-hover: "#C02417"
  on-brand-red: "#FFFFFF"
  papier: "#F4F1EB"
  nebel: "#A9B6BA"
  dark-surface: "#171C1E"
  dark-ground: "#131215"
  dark-surface-raised: "#252A2C"
  dark-on-surface: "#FFFFFF"
  dark-on-surface-2: "#A9B6BA"
  dark-line: "#262C2E"
  dark-primary: "#FFFFFF"
  dark-on-primary: "#171C1E"
  dark-danger: "#FF9C92"
  dark-danger-container: "#3B201E"
  dark-brand-red: "#E6392E"
typography:
  display:
    fontFamily: Inter Tight
    fontSize: 40px
    fontWeight: 600
    lineHeight: 44px
    letterSpacing: -0.028em
  headline:
    fontFamily: Inter Tight
    fontSize: 24px
    fontWeight: 600
    lineHeight: 30px
    letterSpacing: -0.018em
  title:
    fontFamily: Inter Tight
    fontSize: 17px
    fontWeight: 600
    lineHeight: 22px
    letterSpacing: -0.012em
  body:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: 400
    lineHeight: 20px
    fontFeature: '"cv11" 1, "ss01" 0'
  body-lead:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: 400
    lineHeight: 24px
  label:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: 600
    lineHeight: 18px
    letterSpacing: -0.005em
  meta:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: 400
    lineHeight: 16px
  code:
    fontFamily: IBM Plex Mono
    fontSize: 12px
    fontWeight: 400
    lineHeight: 18px
  code-lg:
    fontFamily: IBM Plex Mono
    fontSize: 14px
    fontWeight: 500
    lineHeight: 20px
rounded:
  sm: 4px
  field: 12px
  card: 24px
  full: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
  2xl: 32px
  3xl: 48px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: 18px
    height: 40px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-primary-pressed:
    backgroundColor: "{colors.primary-pressed}"
  button-primary-popup:
    height: 44px
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: 18px
    height: 40px
  button-secondary-hover:
    backgroundColor: "{colors.ground}"
  button-quiet:
    textColor: "{colors.on-surface}"
    typography: "{typography.label}"
    padding: 10px
    height: 40px
  button-danger:
    backgroundColor: "{colors.danger-container}"
    textColor: "{colors.danger}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: 18px
    height: 40px
  button-danger-hover:
    backgroundColor: "{colors.danger-container-hover}"
  button-cta:
    backgroundColor: "{colors.brand-red}"
    textColor: "{colors.on-brand-red}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: 18px
    height: 44px
  button-cta-hover:
    backgroundColor: "{colors.brand-red-hover}"
  tile:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.field}"
    size: 48px
  tile-page:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.card}"
    size: 80px
  tile-danger:
    backgroundColor: "{colors.danger-container}"
    textColor: "{colors.danger}"
    rounded: "{rounded.field}"
    size: 48px
  notice-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    padding: 12px
    width: 340px
  popup:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.on-surface}"
    padding: 12px
    width: 360px
  popup-tile:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.card}"
    padding: 16px
  sheet:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.card}"
    padding: 16px
  dialog:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.card}"
    padding: 24px
    width: 440px
  disclosure:
    textColor: "{colors.on-surface}"
    typography: "{typography.label}"
    height: 32px
  code-field:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.on-surface}"
    typography: "{typography.code}"
    rounded: "{rounded.field}"
    padding: 12px
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.field}"
    padding: 12px
    height: 40px
  input-field-error:
    textColor: "{colors.danger}"
  search-field:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.full}"
    height: 40px
  switch:
    backgroundColor: "{colors.focus}"
    rounded: "{rounded.full}"
    width: 44px
    height: 26px
  segmented:
    backgroundColor: "{colors.surface-cool}"
    rounded: "{rounded.full}"
    padding: 3px
  toast:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body}"
    rounded: "{rounded.full}"
    height: 44px
  nav-rail:
    backgroundColor: "{colors.ground}"
    width: 240px
  nav-item-active:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.field}"
    height: 40px
  banner-error:
    backgroundColor: "{colors.danger-container}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.field}"
    padding: 16px
  button-danger-pressed:
    textColor: "{colors.danger-pressed}"
  button-secondary-outline:
    backgroundColor: "{colors.line-strong}"
    height: 1px
  button-quiet-underline:
    backgroundColor: "{colors.nebel}"
    height: 1px
  switch-off:
    backgroundColor: "{colors.line-strong}"
    rounded: "{rounded.full}"
    width: 44px
    height: 26px
  divider:
    backgroundColor: "{colors.line}"
    height: 1px
  text-secondary:
    textColor: "{colors.on-surface-2}"
    typography: "{typography.body}"
  text-meta:
    textColor: "{colors.on-surface-3}"
    typography: "{typography.meta}"
  page-quiet:
    backgroundColor: "{colors.papier}"
    textColor: "{colors.on-surface}"
  dark-page:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-on-surface}"
  dark-popup:
    backgroundColor: "{colors.dark-ground}"
    textColor: "{colors.dark-on-surface}"
  dark-popup-tile:
    backgroundColor: "{colors.dark-surface-raised}"
    textColor: "{colors.dark-on-surface-2}"
    rounded: "{rounded.card}"
  dark-divider:
    backgroundColor: "{colors.dark-line}"
    height: 1px
  dark-button-primary:
    backgroundColor: "{colors.dark-primary}"
    textColor: "{colors.dark-on-primary}"
    rounded: "{rounded.full}"
    height: 40px
  dark-button-danger:
    backgroundColor: "{colors.dark-danger-container}"
    textColor: "{colors.dark-danger}"
    rounded: "{rounded.full}"
    height: 40px
  dark-logo-diamond:
    backgroundColor: "{colors.dark-brand-red}"
    size: 10px
  dark-button-cta:
    backgroundColor: "{colors.brand-red}"
    textColor: "{colors.on-brand-red}"
    rounded: "{rounded.full}"
    height: 44px
---

# Bastion Shield UI

## Overview

Bastion Shield protects people from ads, trackers, ClickFix commands and
look-alike domains. Most people meet the UI at a tense moment: a page was
blocked or a command was stopped. Every surface therefore says at a glance
what happened and what to do next.

One pattern carries the whole product: a **tile** with a pictogram, a short
**title** (3 to 5 words), at most **one sentence**, and details behind a
**disclosure**. Swiss German copy (ss, «Guillemets», formal «Sie»), sentence
case, verb + noun button labels.

The design in Paper lives on the page «Bastion Shield UI Optimised» of the
file «Bastion GmbH». Artboard codes (P01, N01, S01, DB01, D01, …) are used in
`docs/UI-OPTIMISED.md` to map screens to code.

## Colors

Ink on white with cool Gletscher greys. One dark primary per view.

- **Primary** `#171C1E`: text and the single primary button. Pressed and
  hover states get more contrast than rest, never less.
- **Ink 2 / 3** `#4C575D` (7.6:1) and `#5F6B71` (5.6:1): secondary text and
  meta. Nothing below 4.5:1 for text.
- **Line strong** `#798186` (3.9:1): outlines of secondary buttons, fields
  and the off switch. Every control boundary reaches 3:1.
- **Danger** `#A3231A` on `#FBEAE8` (6.9:1), a muted Bundesrot: destructive
  actions (Löschen, Entfernen, Zurücksetzen), confirming a risky page, and
  error or validation messages. Not for neutral status such as «gesperrt»
  or a nearly full budget; those use ink plus an icon.
- **Brand red** `#DA291C`: the logo diamond and the «Cyber-Vorfall?» call to
  action only. The CTA keeps `#DA291C` in dark mode too: white on the
  lighter `#E6392E` is only 4.2:1. `#E6392E` stays for the logo diamond.
- **Dark**: surfaces `#171C1E` / `#131215` / `#252A2C`, text white and
  `#A9B6BA`, dividers `#262C2E` (`#30373A` on `#252A2C` surfaces). Light
  lines on dark read stronger than dark lines on light, so dark dividers sit
  closer to their ground than `#D7DDDF` does on white. Control outlines that
  must reach 3:1 stay at `#727C7F`; primary inverts to white, tiles invert to white with a dark
  pictogram, danger becomes `#FF9C92` on `#3B201E`.

## Typography

Inter for UI, Inter Tight for titles, IBM Plex Mono for domains, commands,
counts in code and keyboard keys. Self-hosted as «Bastion Inter», «Bastion
Inter Tight» and «Bastion Plex Mono» (`font-display: swap`).

Scale: 12 meta, 14 UI and sentences, 16 page lead, 17 title, 24 section,
40 page title. Never below 12px. Tabular numbers for every figure that is
compared. Numbers use the Swiss format (`Intl.NumberFormat('de-CH')`:
1'248) and a non-breaking space before the unit (612 Zeichen, 1.2 MB).

## Layout

Spacing follows 4, 8, 12, 16, 24, 32, 48. Content is left aligned.

- Popup: 360px wide, ground `#F2F4F5`, tiles 24px radius, 12px gap.
- In-page notice card: `min(340px, 100vw - 24px)`, 12px from the top right.
- Dashboard tab: 240px rail, content padding 48, max-width 880.
- Expanded popup (panel): 760×560, 200px rail, content padding 24, the
  content scrolls with a fade at the bottom.
- Extension pages (blocked, bounce, welcome): one column, max 560px of text.

Every layout handles short, average and very long content: hosts are cut in
the middle (start and TLD stay visible, full value in a disclosure or
`title`), names at the end, commands wrap with `overflow-wrap: anywhere`
inside a field of at most 6 lines that scrolls with
`overscroll-behavior: contain`.

## Elevation & Depth

Depth comes from tone first. Floating surfaces (notice card, dialog, sheet,
toast) add a 1px line plus two shadow layers, near and far:
`0 1px 2px rgb(23 28 30 / .06), 0 10px 28px rgb(23 28 30 / .14)`. Dark mode
uses black shadows at higher opacity. Dialogs and sheets sit on a scrim
(`#171C1E` at 45 %).

## Shapes

Radii are concentric: card 24 with 12 padding contains fields and tiles of
12. Buttons, toasts, search fields and segmented controls are pills. Page
tiles are 80px with radius 24.

## Components

Buttons are 40px high on pages and 44px in the popup. Order: primary first
(left), then secondary, then quiet. Quiet buttons are underlined so they read
as actions without colour. Loading keeps the label and adds a spinner after a
short delay. Disabled is a last resort; prefer validating on submit.

The filter editor is one bordered box (1px `line`, radius 12) with every
inner divider in the same 1px `line`: header, gutter and footer never mix
line weights or colours. The gutter sizes to the widest line number plus
12px on both sides and right-aligns the digits, so the column reads
centred while digits stay aligned when the count grows (999 → 1'000).

Disclosures («Befehl ansehen», «Details», «Was geteilt wird») are buttons
with `aria-expanded` and a 32px hit area. Tiles are decorative
(`aria-hidden="true"`); the title carries the meaning.

Toasts are polite live regions, at most 420px wide and 3 stacked. Reversible
actions (remove a list, remove a site) use a toast with «Rückgängig» instead
of a confirmation. Irreversible ones (Verlauf löschen, Alles zurücksetzen)
use a dialog whose buttons name the outcome («Verlauf löschen» /
«Verlauf behalten»); «Alles zurücksetzen» also needs a checkbox.

## Do's and Don'ts

- Do say what happened in the title and what to do in one sentence.
- Do mark domains, commands, keys and «Bastion Shield» with `translate="no"`.
- Do keep focus visible (2px `#2A3134`, 2px offset), trap it in dialogs and
  sheets, start on the safe action and return it to the trigger on close.
- Do give every target at least 24px, 32px for links in cards and 44px in
  the popup; extend small targets with an invisible hit area.
- Do end labels that open a further step with «…» (Trotzdem öffnen…).
- Do honour `prefers-reduced-motion`; animate only `transform` and `opacity`,
  never `transition: all`.
- Do set `color-scheme` and `theme-color` on extension pages.
- Do design empty, dense, error, loading, locked (by organisation) and dark
  states for every screen.
- Don't use colour alone for status; pair it with an icon and text.
- Don't use Bundesrot for anything but the logo and «Cyber-Vorfall?».
- Don't use the danger red for neutral status.
- Don't put essential information in tooltips; use inline disclosures.
- Don't let text overflow its container; truncate, wrap or scroll inside it.
- Don't write more than one sentence where a title and a disclosure do.
- Don't use the middle dot «·» as a separator; use a spaced hyphen
  («1'204 Zeilen - 38 KB von 1 MB»).
