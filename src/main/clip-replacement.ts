// Bastion Shield — the text the clipboard guard writes instead of a blocked
// command. Its own module so that code which only needs the constant
// (clipguard.js, the e2e specs) does not pull in the detector and its rule
// texts (antivirus engines have flagged transpiled copies of those).
//
// SPDX-License-Identifier: GPL-3.0-or-later

/** What the guard writes instead of a blocked command. Plain ASCII, harmless in any shell (a comment line). */
export const CLIP_REPLACEMENT =
  '# Bastion Shield blocked a command this page tried to put on your clipboard. Do not paste commands from websites into Run, Terminal or PowerShell.';
