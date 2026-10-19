// Bastion Shield — clipboard guard detector (pure; bundled into
// dist/main/clipguard.js and unit-tested in node).
//
// ClickFix / "fake CAPTCHA" pages put a command on the clipboard and tell the
// user to paste it into Win+R, a terminal or PowerShell. detectDangerousCommand
// recognises such payloads; decideClip applies the allow/deny rule:
//
//   * A native copy the user made (Ctrl+C, context menu) whose payload is the
//     user's selection is always allowed: the user picked visible text.
//   * 'high' payloads (lure comments such as "# I am not a robot", encoded or
//     hidden PowerShell, mshta/rundll32/regsvr32/msiexec with a URL, certutil
//     -urlcache, bitsadmin, base64 piped into a shell, scripts fetched from a
//     raw IP or over plain http, ...) are replaced whenever the page wrote
//     them: by writeText/write, by setData in a copy handler that differs
//     from the selection, or by a script-triggered execCommand('copy').
//   * 'medium' payloads (the download-and-run one-liners that real install
//     docs show: `curl -fsSL https://… | sh`, `irm https://… | iex`,
//     Chocolatey's DownloadString) are allowed when the same text is visible
//     on the page (copy buttons next to a code block), and replaced when the
//     page writes them from nowhere (hidden textarea, string in a script).
//
// The detector works on a de-obfuscated copy: lower case, cmd carets and
// PowerShell backtick escapes removed, empty quote pairs dropped, Unicode
// dashes/quotes folded, zero-width characters removed, whitespace collapsed.
// Only the first MAX_SCAN characters are examined (lure payloads are short;
// a page that pads a payload beyond that gets it replaced as 'high').
//
// SPDX-License-Identifier: GPL-3.0-or-later

export type ClipSeverity = 'high' | 'medium';

export interface ClipVerdict {
  severity: ClipSeverity;
  /** Short machine-readable rule name (tests, logs). */
  rule: string;
}

/** Characters of a payload that are examined. */
export const MAX_SCAN = 16_384;

/** What the guard writes instead of a blocked command. Plain ASCII, harmless in any shell (a comment line). */
export const CLIP_REPLACEMENT =
  '# Bastion Shield blocked a command this page tried to put on your clipboard. Do not paste commands from websites into Run, Terminal or PowerShell.';

/** Lower-cased, de-obfuscated, whitespace-collapsed form used by the rules. */
export function normalizeCommand(text: string): string {
  let s = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  s = s.toLowerCase();
  s = s.replace(/[​-‍⁠﻿­]/g, '');
  s = s.replace(/[‐-―−]/g, '-');
  s = s.replace(/[‘’‚‛]/g, "'").replace(/[“”„‟]/g, '"');
  s = s.replace(/\^/g, ''); // cmd escape: p^o^w^e^r^s^h^e^l^l
  s = s.replace(/`(?=[a-z0-9])/g, ''); // PowerShell escape: i`e`x
  s = s.replace(/""|''/g, ''); // empty quote pairs: pow""ershell
  s = s.replace(/\s+/g, ' ').trim();
  return s;
}

/** Whitespace-collapsed form used to compare a payload with the selection or page text. */
export function collapseWs(text: string): string {
  return text.replace(/[\s ]+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Rules (on normalizeCommand output)
// ---------------------------------------------------------------------------

const PS = String.raw`\b(?:powershell|pwsh)(?:\.exe)?\b`;
/** A program that starts a shell or a LOLBin, i.e. something worth luring a paste into. */
const LAUNCHER = String.raw`\b(?:powershell|pwsh|cmd|mshta|msiexec|rundll32|regsvr32|conhost|wscript|cscript|curl|wget|bash|zsh|sh|osascript|certutil|bitsadmin|finger|iex|irm|iwr|forfiles|schtasks|invoke-expression|invoke-webrequest|invoke-restmethod)(?:\.exe)?\b`;
const DOWNLOAD = String.raw`(?:\birm\b|\biwr\b|invoke-restmethod|invoke-webrequest|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|\bcurl\b|\bwget\b|https?:\/\/)`;
const EXEC = String.raw`(?:\biex\b|invoke-expression|\.invoke\(|scriptblock\]?::create|\|\s*iex\b|&\s*\(|start-process)`;
const SHELL_SINK = String.raw`\|\s*(?:sudo\s+)?(?:\/bin\/|\/usr\/bin\/)?(?:ba|z|da|k|c)?sh\b`;
const IPV4_URL = String.raw`(?:https?:\/\/|\b)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/`;

interface Rule {
  rule: string;
  severity: ClipSeverity;
  test: (s: string) => boolean;
}

const re = (src: string): RegExp => new RegExp(src);

const R_LURE = re(
  String.raw`#.*(?:not a robot|not a bot|captcha|verification (?:id|code|hash|number|token|step)|ray id|cloudflare|human verification|i am human|i'm human|you are human|you're human|security check|press enter)`,
);
const R_LAUNCHER = re(LAUNCHER);
const R_PS = re(PS);
const R_PS_ENC = re(PS + String.raw`.*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+["']?[a-z0-9+/=]{16,}`);
const R_PS_HIDDEN = re(PS + String.raw`.*\s-(?:w|wi|win|wind|windo|window|windows|windowst|windowstyle)\s+["']?(?:h|hi|hid|hidd|hidde|hidden|1|min|minimized)\b`);
const R_DOWNLOAD = re(DOWNLOAD);
const R_EXEC = re(EXEC);
const R_B64_EXEC = re(String.raw`frombase64string`);
const R_MSHTA = re(String.raw`\bmshta(?:\.exe)?\s+["']?(?:https?:|\\\\|vbscript:|javascript:|about:)`);
const R_MSHTA_ANY = re(String.raw`\bmshta(?:\.exe)?\b.*https?:\/\/`);
const R_RUNDLL = re(String.raw`\b(?:rundll32|regsvr32)(?:\.exe)?\b.*(?:https?:\/\/|\\\\[a-z0-9]|javascript:|\/i:|scrobj|davwwwroot)`);
const R_CERTUTIL = re(String.raw`\bcertutil(?:\.exe)?\b.*\s-(?:urlcache|verifyctl|decode|decodehex)\b`);
const R_BITSADMIN = re(String.raw`\bbitsadmin(?:\.exe)?\b.*\/(?:transfer|addfile|create)\b`);
const R_MSIEXEC = re(String.raw`\bmsiexec(?:\.exe)?\b.*(?:https?:\/\/|\\\\[a-z0-9])`);
const R_CMD = re(String.raw`\bcmd(?:\.exe)?\s+\/[ckr]\b`);
const R_CMD_PAYLOAD = re(String.raw`https?:\/\/|\b(?:powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|msiexec|rundll32|regsvr32|wscript|cscript|finger|conhost)\b|%temp%|%appdata%|%localappdata%|\\\\[a-z0-9]`);
const R_CONHOST = re(String.raw`\bconhost(?:\.exe)?\b.*--headless`);
const R_FINGER = re(String.raw`\bfinger(?:\.exe)?\s+\S+@\S+.*\|\s*(?:cmd|powershell|pwsh|sh|bash)\b`);
const R_WSCRIPT = re(String.raw`\b(?:wscript|cscript)(?:\.exe)?\b.*(?:https?:\/\/|\\\\[a-z0-9])`);
const R_WEBDAV = re(String.raw`\\\\[^\\\s]+@(?:ssl|\d+)\\davwwwroot`);
const R_B64_SHELL = re(String.raw`base64\s+(?:-d|--decode|-D)\b.*` + SHELL_SINK);
const R_ECHO_B64_SHELL = re(String.raw`\becho\s+["']?[a-z0-9+/=]{24,}["']?\s*\|\s*base64\b`);
const R_OSASCRIPT = re(String.raw`\bosascript\b.*(?:do shell script|https?:\/\/|curl|password|display dialog)`);
const R_CURL_SHELL = re(String.raw`\b(?:curl|wget)\b[^|;&]*` + SHELL_SINK);
const R_SHELL_SUBST = re(String.raw`\b(?:ba|z|da|k)?sh\s+(?:-c\s+["']?\$\(|<\()\s*(?:curl|wget)\b`);
const R_IP_URL = re(IPV4_URL);
const R_HTTP_URL = re(String.raw`\bhttp:\/\/`);
const R_INSECURE = re(String.raw`\s(?:-k|--insecure|--no-check-certificate)\b`);
const R_PS_DOWNLOAD_EXEC = re(String.raw`(?:` + EXEC + String.raw`).*` + DOWNLOAD + String.raw`|` + DOWNLOAD + String.raw`.*` + EXEC);

const RULES: readonly Rule[] = [
  // Lure: "<command> # I am not a robot - reCAPTCHA Verification ID: 1234".
  {
    rule: 'lure-comment',
    severity: 'high',
    test: (s) => {
      const hash = s.indexOf('#');
      return hash > 0 && R_LURE.test(s.slice(hash)) && R_LAUNCHER.test(s.slice(0, hash));
    },
  },
  { rule: 'powershell-encoded', severity: 'high', test: (s) => R_PS_ENC.test(s) },
  { rule: 'powershell-hidden', severity: 'high', test: (s) => R_PS_HIDDEN.test(s) && (R_DOWNLOAD.test(s) || R_EXEC.test(s) || R_B64_EXEC.test(s)) },
  { rule: 'base64-exec', severity: 'high', test: (s) => R_B64_EXEC.test(s) && (R_EXEC.test(s) || R_PS.test(s)) },
  { rule: 'mshta', severity: 'high', test: (s) => R_MSHTA.test(s) || R_MSHTA_ANY.test(s) },
  { rule: 'rundll32-regsvr32', severity: 'high', test: (s) => R_RUNDLL.test(s) },
  { rule: 'certutil', severity: 'high', test: (s) => R_CERTUTIL.test(s) },
  { rule: 'bitsadmin', severity: 'high', test: (s) => R_BITSADMIN.test(s) },
  { rule: 'msiexec-remote', severity: 'high', test: (s) => R_MSIEXEC.test(s) },
  { rule: 'cmd-payload', severity: 'high', test: (s) => R_CMD.test(s) && R_CMD_PAYLOAD.test(s) },
  { rule: 'conhost-headless', severity: 'high', test: (s) => R_CONHOST.test(s) },
  { rule: 'finger-pipe', severity: 'high', test: (s) => R_FINGER.test(s) },
  { rule: 'wscript-remote', severity: 'high', test: (s) => R_WSCRIPT.test(s) },
  { rule: 'webdav-unc', severity: 'high', test: (s) => R_WEBDAV.test(s) },
  { rule: 'base64-shell', severity: 'high', test: (s) => R_B64_SHELL.test(s) || (R_ECHO_B64_SHELL.test(s) && /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/.test(s)) },
  { rule: 'osascript', severity: 'high', test: (s) => R_OSASCRIPT.test(s) },
  // Download-and-run one-liners: legitimate in install docs unless fetched insecurely.
  {
    rule: 'curl-shell',
    severity: 'medium',
    test: (s) => R_CURL_SHELL.test(s) || R_SHELL_SUBST.test(s) || (/\b(?:ba|z)?sh\b.*\$\(\s*(?:curl|wget)\b/.test(s)),
  },
  { rule: 'powershell-download-exec', severity: 'medium', test: (s) => R_PS_DOWNLOAD_EXEC.test(s) && (R_PS.test(s) || /\b(?:iex|irm|iwr)\b/.test(s)) },
];

/**
 * The verdict for a clipboard payload, or null when it does not look like a
 * dangerous command. Never throws.
 */
export function detectDangerousCommand(text: unknown): ClipVerdict | null {
  if (typeof text !== 'string' || text.length < 6) return null;
  let s: string;
  try {
    s = normalizeCommand(text);
  } catch {
    return null;
  }
  for (const r of RULES) {
    let matched = false;
    try {
      matched = r.test(s);
    } catch {
      matched = false;
    }
    if (!matched) continue;
    if (r.severity === 'medium' && (R_IP_URL.test(s) || R_HTTP_URL.test(s) || R_INSECURE.test(s))) {
      // Scripts from a raw IP, over plain http or with TLS checks off: no install doc does that.
      return { severity: 'high', rule: `${r.rule}-insecure` };
    }
    return { severity: r.severity, rule: r.rule };
  }
  // A payload padded beyond the scanned window that still starts like a command.
  if (text.length > MAX_SCAN && R_LAUNCHER.test(s.slice(0, 256))) return { severity: 'high', rule: 'oversized' };
  return null;
}

// ---------------------------------------------------------------------------
// Allow / deny
// ---------------------------------------------------------------------------

export interface ClipContext {
  /**
   * The payload comes from a native copy/cut the user started (keyboard or
   * context menu), not from writeText/write or a script-triggered
   * execCommand.
   */
  userCopy: boolean;
  /** The current selection text (input/textarea selection or document selection). */
  selection: string;
  /** Lazily answers "is this text visible on the page?" (page text contains it). */
  visible: () => boolean;
}

/** True when the guard must replace `text`. */
export function decideClip(text: string, verdict: ClipVerdict | null, ctx: ClipContext): boolean {
  if (verdict === null) return false;
  const sel = collapseWs(ctx.selection);
  if (ctx.userCopy && sel !== '' && collapseWs(text) === sel) return false;
  if (verdict.severity === 'high') return true;
  try {
    return !ctx.visible();
  } catch {
    return true;
  }
}

/** Haystack contains needle after whitespace collapsing (the visible-text check). */
export function containsCollapsed(haystack: string, needle: string): boolean {
  const n = collapseWs(needle);
  if (n === '') return false;
  return collapseWs(haystack).includes(n);
}

/** Sample sent to the service worker / popup: single line, at most `max` characters. */
export function clipSample(text: string, max = 200): string {
  const s = collapseWs(text.length > max * 4 ? text.slice(0, max * 4) : text);
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}
