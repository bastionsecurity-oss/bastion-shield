// Bastion Shield — clipboard guard detector (pure; bundled into
// dist/content/nerd-relay.js and dist/content/cosmetic.js, unit-tested in
// node).
//
// ClickFix / "fake CAPTCHA" pages put a command on the clipboard and tell the
// user to paste it into Win+R, a terminal or PowerShell. detectDangerousCommand
// recognises such payloads; decideClip applies the allow/deny rule:
//
//   * A native copy the user made (Ctrl+C, context menu) whose payload is the
//     user's selection is always allowed: the user picked visible text.
//   * 'high' payloads (lure comments such as "# I am not a robot", encoded,
//     hidden or policy-bypassing PowerShell, mshta/rundll32/regsvr32/msiexec
//     with a URL, certutil -urlcache, bitsadmin, base64 piped into a shell,
//     scripts fetched from a raw IP or over plain http, every 'high' pattern
//     of uBO's ClickFix filter, ...) are replaced whenever the page wrote
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
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
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
export { CLIP_REPLACEMENT } from './clip-replacement.ts';

/**
 * Lower-cased and de-obfuscated, whitespace kept as is: zero-width
 * characters removed, Unicode dashes/quotes folded, cmd carets, PowerShell
 * backtick escapes and empty quote pairs dropped.
 */
export function deobfuscate(text: string): string {
  let s = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  s = s.toLowerCase();
  s = s.replace(/[​-‍⁠﻿­]/g, '');
  s = s.replace(/[‐-―−]/g, '-');
  s = s.replace(/[‘’‚‛]/g, "'").replace(/[“”„‟]/g, '"');
  s = s.replace(/\^/g, ''); // cmd escape: p^o^w^e^r^s^h^e^l^l
  s = s.replace(/`(?=[a-z0-9])/g, ''); // PowerShell escape: i`e`x
  s = s.replace(/""|''/g, ''); // empty quote pairs: pow""ershell
  return s;
}

/** Lower-cased, de-obfuscated, whitespace-collapsed form used by most rules. */
export function normalizeCommand(text: string): string {
  return deobfuscate(text).replace(/\s+/g, ' ').trim();
}

/** Whitespace-collapsed form used to compare a payload with the selection or page text. */
export function collapseWs(text: string): string {
  return text.replace(/[\s ]+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
//
// Every rule sees three forms of the payload (Forms):
//   s  normalizeCommand: one line, whitespace collapsed (most rules);
//   l  the same per line: horizontal whitespace collapsed, lines trimmed,
//      empty lines dropped. Rules anchored at a line start use it with the
//      `m` flag, as uBO's filter (flags `msi`) anchors with `^`;
//   w  deobfuscate only: whitespace kept (padding tricks such as
//      "<command>      # ..." that collapsing would hide).
//
// uBO's generic ClickFix filter (uBlock filters – Badware risks:
// `##+js(prevent-clipboard-write, <regex>, domAlert, …, excludeMatches, …)`)
// is ported rule by rule below (names in UBO_PORTED_RULES), so the guard is at
// least as strong where uBO's scriptlet does not run (its ~95 excluded
// developer sites, writes through clipboard.write or setData). Severity:
//   'high'   unambiguous attack shapes: no page has a reason to hand a
//            visitor these (hidden-window or policy-bypassing PowerShell
//            launched from the Run box, cmd tricks, lure comments, ...).
//   'medium' download-and-run one-liners that real install docs print
//            (curl … | sh, irm … | iex, msiexec of a local package, a
//            bash line with an aligned comment): allowed when visible on
//            the page (copy buttons next to a code block), blocked otherwise.

export interface Forms {
  s: string;
  l: string;
  w: string;
}

export function commandForms(text: string): Forms {
  const w = deobfuscate(text);
  const s = w.replace(/\s+/g, ' ').trim();
  const l = w
    .split(/\r\n|\r|\n|\u2028|\u2029/)
    .map((x) => x.replace(/\s+/g, ' ').trim())
    .filter((x) => x !== '')
    .join('\n');
  return { s, l, w };
}

const PS = String.raw`\b(?:powershell|pwsh)(?:\.exe)?\b`;
/** A line that starts with a program (after optional quotes/@/parens), or a program given by path. */
const LS = String.raw`(?:^["'@(]*|\\)`;
/** PowerShell launched as a program: at a line start or after a path separator (uBO: `(^|\\)powershell`). */
const PS_LAUNCH = LS + String.raw`(?:powershell|pwsh)(?:\.exe)?\b`;
/** A program that starts a shell or a LOLBin, i.e. something worth luring a paste into. */
const LAUNCHER = String.raw`\b(?:powershell|pwsh|cmd|mshta|msiexec|rundll32|regsvr32|conhost|wscript|cscript|curl|wget|bash|zsh|sh|osascript|certutil|bitsadmin|finger|iex|irm|iwr|forfiles|schtasks|invoke-expression|invoke-webrequest|invoke-restmethod)(?:\.exe)?\b`;
const DOWNLOAD = String.raw`(?:\birm\b|\biwr\b|invoke-restmethod|invoke-webrequest|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|\bcurl\b|\bwget\b|https?:\/\/)`;
const EXEC = String.raw`(?:\biex\b|invoke-expression|\.invoke\(|scriptblock\]?::create|\|\s*iex\b|&\s*\(|start-process)`;
const SHELL_SINK = String.raw`\|\s*(?:sudo\s+)?(?:\/bin\/|\/usr\/bin\/)?(?:ba|z|da|k|c)?sh\b`;
const IPV4_URL = String.raw`(?:https?:\/\/|\b)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/`;
/** Prefixes of -WindowStyle (PowerShell accepts any unambiguous prefix). */
const WINDOWSTYLE = String.raw`w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?`;
/** Horizontal padding characters (spaces, tabs, Unicode spaces). */
const PAD = String.raw`[ \t   -   　]`;

interface Rule {
  rule: string;
  severity: ClipSeverity;
  test: (f: Forms) => boolean;
}

/** A regex compiled on first use: cosmetic.js loads this module in every frame, most never test a payload. */
interface LazyRe {
  test(s: string): boolean;
}
const re = (src: string, flags = ''): LazyRe => {
  let r: RegExp | null = null;
  return { test: (s: string) => (r ??= new RegExp(src, flags)).test(s) };
};
/** Line-anchored regex for the `l` form. */
const rl = (src: string): LazyRe => re(src, 'm');

const R_LURE = re(
  String.raw`#.*(?:not a robot|not a bot|captcha|verification (?:id|code|hash|number|token|step)|ray id|cloudflare|human verification|i am human|i'm human|you are human|you're human|security check|press enter)`,
);
const R_LAUNCHER = re(LAUNCHER);
const R_PS = re(PS);
const R_PS_ENC = re(PS + String.raw`.*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+["']?[a-z0-9+/=]{16,}`);
// -WindowStyle Hidden / Minimized / Maximized (uBO: `-w(indowStyle)? h(idden)?`, `-w[a-z]* m[a-z]* `), or 1 / 2.
const R_PS_HIDDEN = re(PS + String.raw`.*\s-` + WINDOWSTYLE + String.raw`\s+["']?(?:h[a-z]*|m[a-z]*|1|2)\b`);
const R_DOWNLOAD = re(DOWNLOAD);
const R_EXEC = re(EXEC);
const R_B64_EXEC = re(String.raw`frombase64string`);
const R_MSHTA = re(String.raw`\bmshta(?:\.exe)?\s+["']?(?:https?:|\\\\|vbscript:|javascript:|about:)`);
const R_MSHTA_ANY = re(String.raw`\bmshta(?:\.exe)?\b.*https?:\/\/`);
const R_MSHTA_START = rl(String.raw`^["'@(]*mshta(?:\.exe)?["']?\s`);
const R_RUNDLL = re(String.raw`\b(?:rundll32|regsvr32)(?:\.exe)?\b.*(?:https?:\/\/|\\\\[a-z0-9]|javascript:|\/i:|scrobj|davwwwroot)`);
const R_CERTUTIL = re(String.raw`\bcertutil(?:\.exe)?\b.*\s-(?:urlcache|verifyctl|decode|decodehex)\b`);
const R_BITSADMIN = re(String.raw`\bbitsadmin(?:\.exe)?\b.*\/(?:transfer|addfile|create)\b`);
const R_MSIEXEC = re(String.raw`\bmsiexec(?:\.exe)?\b.*(?:https?:\/\/|\\\\[a-z0-9])`);
const R_MSIEXEC_START = rl(String.raw`^["'@(]*msiexec(?:\.exe)?["']?\s`);
const R_CMD = re(String.raw`\bcmd(?:\.exe)?\s+\/[ckr]\b`);
const R_CMD_PAYLOAD = re(String.raw`https?:\/\/|\b(?:powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|msiexec|rundll32|regsvr32|wscript|cscript|finger|conhost)\b|%temp%|%appdata%|%localappdata%|\\\\[a-z0-9]`);
const R_HEADLESS = re(String.raw`\b(?:conhost|cmd)(?:\.exe)?\b.*\s--headless\b`);
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

// Ported from uBO's ClickFix filter (see UBO_PORTED_RULES).
const R_HERESTRING_B64 = rl(String.raw`^(?:(?:ba|z)?sh\s*<<<|curl\s+-kfssl)\s*["']?\$\(\s*echo\b[\s\S]*?\bbase64\s+(?:-d|--decode)\b`);
const R_CMD_FOR_DELIMS = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\bfor\s+\/f\b[\s\S]*?\bdelims\b[\s\S]*?\bpow`);
const R_PS_NOP = rl(PS_LAUNCH + String.raw`[\s\S]*?\s-nop\b`);
const R_PS_BYPASS = rl(PS_LAUNCH + String.raw`[\s\S]*?\s-(?:ep[a-z]*|ex[a-z]*)\s+["']?(?:b|bypass|u|unrestricted)\b`);
const R_PS_LAUNCH_EXEC = rl(PS_LAUNCH + String.raw`[\s\S]*?(?:\biex\s*\(|invoke-expression|invoke-webrequest|-usebasicparsing\b)`);
const R_PS_IRM_RELAUNCH = rl(PS_LAUNCH + String.raw`[\s\S]*?\birm\s[\s\S]*?\.[a-z]+\/[\s\S]*?powershell`);
const R_CMD_NOP_IEX = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\/c\s[\s\S]*?\s-nop\s[\s\S]*?\biex\b`);
const R_LAUNCHER_RECAPTCHA = rl(String.raw`^["'@(]*(?:cmd|powershell|pwsh|bash|sh|zsh|osascript)(?:\.exe)?\b[\s\S]*?recaptcha`);
const R_PADDED_WIN = rl(String.raw`^\s*["'@(]*(?:cmd|powershell|pwsh|osascript)(?:\.exe)?\b[\s\S]*?(?:#\s*verification|` + PAD + `{5,}#|#` + PAD + `{5,})`);
const R_PADDED_SH = rl(String.raw`^\s*["'@(]*(?:bash|sh|zsh)\b[\s\S]*?(?:#\s*verification|` + PAD + `{5,}#|#` + PAD + `{5,})`);
const R_SHELL_C_CURL = rl(String.raw`^["'(]*(?:\/(?:usr\/)?bin\/)?(?:ba|z)?sh\s+-c\b[\s\S]*?\bcurl\b`);
const R_PYTHON_C = rl(String.raw`^["'(]*(?:python3?|py)(?:\.exe)?\s+-c\b[\s\S]*?\b(?:exec|urllib|subprocess)\b`);
const R_ECHO_BASE64_SHELL = rl(String.raw`^echo\s[\s\S]*?base64\s[\s\S]*?\b(?:bash|osascript|z?sh)\b`);
const R_OPENSSL_B64 = re(String.raw`\bopenssl\s+(?:base64|enc)\b.*\s-d\b`);
const R_CURL_CHMOD = rl(String.raw`^curl\b[\s\S]*?\bchmod\s+\+x\b[\s\S]*?&&`);
const R_CURL_TMP = rl(String.raw`^curl\b[\s\S]*?\s-o\b[\s\S]*?\/tmp\/[\s\S]*?&&`);
const R_NETCAT = re(String.raw`\bnc(?:at)?(?:\.exe)?\s.*\s-e\s+\/bin\/(?:ba|z)?sh\b`);
const R_TMP_CHMOD = rl(String.raw`^\/tmp\/[\s\S]*?\bchmod\s+\+x\b[\s\S]*?&&`);
const R_WGET_QUIET = rl(String.raw`^wget\s+-q[\s\S]*?\.(?:sh|py|bin|elf)\b`);
const R_CMD_CERTUTIL = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\bcertutil\b[\s\S]*?\.(?:exe|bat)\b`);
const R_PCALUA = re(String.raw`\bpcalua(?:\.exe)?\b.*\b(?:curl|powershell|pwsh|saps|cmd|mshta)\b`);
const R_CMDKEY_SCHTASKS = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\bcmdkey\b[\s\S]*?\bschtasks\b`);
const R_INVOKE_COMMAND_B64 = rl(String.raw`^invoke-command\b[\s\S]*?base64string`);
const R_IEX_DOWNLOAD = rl(String.raw`^iex\s*\(\s*(?:irm|iwr)\b`);
const R_IRM_IEX = rl(String.raw`^\(?\s*irm\s[\s\S]*?\biex\b`);
const R_COMSPEC_START_MIN = rl(String.raw`^["'@(]*%comspec%[\s\S]*?\bstart\b[\s\S]*?\/min\b`);
const R_CMD_TEMP_BAT = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\/c\b[\s\S]*?%temp%[\s\S]*?\.bat\b`);
const R_CMD_CMDCMDLINE = rl(String.raw`^["'@(]*cmd(?:\.exe)?\b[\s\S]*?\/c\b[\s\S]*?\bcmdcmdline\b`);
const R_CMD_DELAYED = rl(String.raw`^["'@(]*cmd(?:\.exe)?\s+\/v:on\s+\/q\s+\/c\b`);
const R_CONVERT_COMSPEC = re(String.raw`\bconvert\b.*\$env:comspec\b`);
const R_PS_COMMENT_LURE = rl(String.raw`^<#\s*verification`);
const R_IWR_WSCRIPT = rl(String.raw`^(?:invoke-webrequest|iwr)\b[\s\S]*?\bwscript(?:\.exe)?\b`);
const R_URL_FILENAME_EXE = rl(String.raw`^\$url\b[\s\S]*?\n\$filename\b[\s\S]*?\.exe\b`);

const RULES: readonly Rule[] = [
  // Lure: "<command> # I am not a robot - reCAPTCHA Verification ID: 1234".
  {
    rule: 'lure-comment',
    severity: 'high',
    test: ({ s }) => {
      const hash = s.indexOf('#');
      return hash > 0 && R_LURE.test(s.slice(hash)) && R_LAUNCHER.test(s.slice(0, hash));
    },
  },
  { rule: 'powershell-encoded', severity: 'high', test: ({ s }) => R_PS_ENC.test(s) },
  // A hidden or minimised PowerShell window: no web page has a legitimate reason to hand this out.
  { rule: 'powershell-hidden', severity: 'high', test: ({ s }) => R_PS_HIDDEN.test(s) },
  { rule: 'base64-exec', severity: 'high', test: ({ s }) => R_B64_EXEC.test(s) && (R_EXEC.test(s) || R_PS.test(s)) },
  { rule: 'mshta', severity: 'high', test: ({ s, l }) => R_MSHTA.test(s) || R_MSHTA_ANY.test(s) || R_MSHTA_START.test(l) },
  { rule: 'rundll32-regsvr32', severity: 'high', test: ({ s }) => R_RUNDLL.test(s) },
  { rule: 'certutil', severity: 'high', test: ({ s }) => R_CERTUTIL.test(s) },
  { rule: 'bitsadmin', severity: 'high', test: ({ s }) => R_BITSADMIN.test(s) },
  { rule: 'msiexec-remote', severity: 'high', test: ({ s }) => R_MSIEXEC.test(s) },
  { rule: 'cmd-payload', severity: 'high', test: ({ s }) => R_CMD.test(s) && R_CMD_PAYLOAD.test(s) },
  { rule: 'conhost-headless', severity: 'high', test: ({ s }) => R_HEADLESS.test(s) },
  { rule: 'finger-pipe', severity: 'high', test: ({ s }) => R_FINGER.test(s) },
  { rule: 'wscript-remote', severity: 'high', test: ({ s }) => R_WSCRIPT.test(s) },
  { rule: 'webdav-unc', severity: 'high', test: ({ s }) => R_WEBDAV.test(s) },
  { rule: 'base64-shell', severity: 'high', test: ({ s }) => R_B64_SHELL.test(s) || (R_ECHO_B64_SHELL.test(s) && /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/.test(s)) },
  { rule: 'osascript', severity: 'high', test: ({ s }) => R_OSASCRIPT.test(s) },
  // --- uBO ClickFix filter, high ---
  { rule: 'powershell-noprofile', severity: 'high', test: ({ l }) => R_PS_NOP.test(l) },
  { rule: 'powershell-bypass', severity: 'high', test: ({ l }) => R_PS_BYPASS.test(l) },
  { rule: 'powershell-launch-exec', severity: 'high', test: ({ l }) => R_PS_LAUNCH_EXEC.test(l) },
  { rule: 'powershell-irm-relaunch', severity: 'high', test: ({ l }) => R_PS_IRM_RELAUNCH.test(l) },
  { rule: 'herestring-base64', severity: 'high', test: ({ l }) => R_HERESTRING_B64.test(l) },
  { rule: 'cmd-for-delims', severity: 'high', test: ({ l }) => R_CMD_FOR_DELIMS.test(l) },
  { rule: 'cmd-nop-iex', severity: 'high', test: ({ l }) => R_CMD_NOP_IEX.test(l) },
  { rule: 'cmd-delayed-expansion', severity: 'high', test: ({ l }) => R_CMD_DELAYED.test(l) },
  { rule: 'cmd-temp-bat', severity: 'high', test: ({ l }) => R_CMD_TEMP_BAT.test(l) },
  { rule: 'cmd-cmdcmdline', severity: 'high', test: ({ l }) => R_CMD_CMDCMDLINE.test(l) },
  { rule: 'cmd-certutil', severity: 'high', test: ({ l }) => R_CMD_CERTUTIL.test(l) },
  { rule: 'cmdkey-schtasks', severity: 'high', test: ({ l }) => R_CMDKEY_SCHTASKS.test(l) },
  { rule: 'comspec-start-min', severity: 'high', test: ({ l }) => R_COMSPEC_START_MIN.test(l) },
  { rule: 'pcalua', severity: 'high', test: ({ s }) => R_PCALUA.test(s) },
  { rule: 'invoke-command-base64', severity: 'high', test: ({ l }) => R_INVOKE_COMMAND_B64.test(l) },
  { rule: 'convert-comspec', severity: 'high', test: ({ s }) => R_CONVERT_COMSPEC.test(s) },
  { rule: 'ps-comment-lure', severity: 'high', test: ({ l }) => R_PS_COMMENT_LURE.test(l) },
  { rule: 'iwr-wscript', severity: 'high', test: ({ l }) => R_IWR_WSCRIPT.test(l) },
  { rule: 'url-filename-exe', severity: 'high', test: ({ l }) => R_URL_FILENAME_EXE.test(l) },
  { rule: 'launcher-recaptcha', severity: 'high', test: ({ l }) => R_LAUNCHER_RECAPTCHA.test(l) },
  { rule: 'padded-comment', severity: 'high', test: ({ w }) => R_PADDED_WIN.test(w) },
  { rule: 'python-c-exec', severity: 'high', test: ({ l }) => R_PYTHON_C.test(l) },
  { rule: 'echo-base64-shell', severity: 'high', test: ({ l }) => R_ECHO_BASE64_SHELL.test(l) },
  { rule: 'openssl-base64', severity: 'high', test: ({ s }) => R_OPENSSL_B64.test(s) },
  { rule: 'curl-chmod-run', severity: 'high', test: ({ l }) => R_CURL_CHMOD.test(l) },
  { rule: 'curl-tmp-run', severity: 'high', test: ({ l }) => R_CURL_TMP.test(l) },
  { rule: 'tmp-chmod-run', severity: 'high', test: ({ l }) => R_TMP_CHMOD.test(l) },
  { rule: 'netcat-shell', severity: 'high', test: ({ s }) => R_NETCAT.test(s) },
  // Download-and-run one-liners: legitimate in install docs unless fetched insecurely.
  {
    rule: 'curl-shell',
    severity: 'medium',
    test: ({ s }) => R_CURL_SHELL.test(s) || R_SHELL_SUBST.test(s) || /\b(?:ba|z)?sh\b.*\$\(\s*(?:curl|wget)\b/.test(s),
  },
  { rule: 'powershell-download-exec', severity: 'medium', test: ({ s }) => R_PS_DOWNLOAD_EXEC.test(s) && (R_PS.test(s) || /\b(?:iex|irm|iwr)\b/.test(s)) },
  // --- uBO ClickFix filter, medium ---
  { rule: 'shell-c-curl', severity: 'medium', test: ({ l }) => R_SHELL_C_CURL.test(l) },
  { rule: 'iex-download', severity: 'medium', test: ({ l }) => R_IEX_DOWNLOAD.test(l) },
  { rule: 'irm-iex', severity: 'medium', test: ({ l }) => R_IRM_IEX.test(l) },
  { rule: 'wget-quiet-script', severity: 'medium', test: ({ l }) => R_WGET_QUIET.test(l) },
  { rule: 'msiexec-start', severity: 'medium', test: ({ l }) => R_MSIEXEC_START.test(l) },
  // Aligned comments are common in shell docs; on cmd/PowerShell lines they are 'padded-comment' (high).
  { rule: 'padded-comment-shell', severity: 'medium', test: ({ w }) => R_PADDED_SH.test(w) },
];

/**
 * Every alternative of uBO's generic ClickFix regex, mapped to the rule that
 * covers it here (docs and tests; test/content/clipguard.test.ts checks that
 * each one has a positive fixture).
 */
export const UBO_PORTED_RULES: Readonly<Record<string, string>> = {
  // Keys: fnv1a32 (base 36, 7 digits) of each top-level alternative of uBO's
  // regex, as written in the filter. The repository does not carry uBO's
  // patterns verbatim (antivirus engines flag files full of ClickFix
  // shapes); test/content/clipguard.test.ts hashes the alternatives of the
  // cached uBlock list and fails on any it does not find here.
  '0cirywr': 'mshta / msiexec-start', // ^ms(hta|iexec)
  '0y05avd': 'herestring-base64', // ^(bash <<<|curl -kfsSL) $(echo … base64 -d
  '0z2vlq4': 'cmd-payload', // ^cmd /c … curl … .exe|.bat
  '1t0r2es': 'cmd-for-delims', // ^cmd … for /f … delims … pow
  '12rql10': 'powershell-hidden', // powershell … -w(indowStyle) h(idden)
  '1le8gnf': 'powershell-hidden', // powershell … -w* m*
  '0oaa314': 'powershell-noprofile', // powershell … -NoP
  '0q788fj': 'powershell-bypass', // powershell … -e(xecution)p(olicy) b(ypass)
  '1he4jjj': 'powershell-bypass', // powershell … -e(xecution)p(olicy) u(nrestricted)
  '1lzqju6': 'powershell-launch-exec', // powershell … iex(
  '1fy21tz': 'powershell-launch-exec', // powershell … Invoke-Expression
  '1qoyvm9': 'powershell-launch-exec', // powershell … Invoke-WebRequest
  '02sbpxf': 'powershell-launch-exec', // powershell … -UseBasicParsing
  '0amn2p0': 'cmd-nop-iex', // ^cmd … /c … -nop … iex
  '166ea8q': 'launcher-recaptcha', // ^(cmd|powershell) … recaptcha
  '05nq4u4': 'padded-comment', // ^(cmd|powershell) … #(Verification|5 spaces)
  '129nprw': 'padded-comment', // ^(cmd|powershell) … 5 spaces #
  '03co9lv': 'osascript', // ^osascript … curl http
  '0k7y1l8': 'curl-shell', // ^curl -s … | (bash|sh|zsh)
  '0qc26x9': 'shell-c-curl', // ^/bin/(bash|sh|zsh) -c … curl
  '0orx403': 'curl-shell', // ^bash -c … $(curl
  '16u8f4q': 'python-c-exec', // ^python3? -c … exec|urllib|subprocess
  '0w624c2': 'echo-base64-shell', // ^echo … base64 … bash|osascript|sh
  '0ndjjs5': 'openssl-base64', // openssl base64 -d
  '0pcl90f': 'curl-chmod-run', // ^curl … chmod +x … &&
  '11wp002': 'launcher-recaptcha', // ^(bash|sh|osascript) … recaptcha
  '1yxkw50': 'padded-comment / padded-comment-shell', // ^(bash|sh|osascript) … #(Verification|5 spaces)
  '0vgzolg': 'padded-comment / padded-comment-shell', // ^(bash|sh|osascript) … 5 spaces #
  '08l65rw': 'curl-shell', // ^wget … | (bash|sh)
  '1ll2j2m': 'curl-tmp-run', // ^curl … -o … /tmp/ … &&
  '11baznb': 'netcat-shell', // ^nc … -e /bin/(bash|sh)
  '1yu809e': 'tmp-chmod-run', // ^/tmp/ … chmod +x … &&
  '1bx6vqt': 'wget-quiet-script', // ^wget -q … .(sh|py|bin|elf)
  '10wkk57': 'cmd-certutil', // ^cmd … certutil … .exe|.bat
  '14opvku': 'powershell-irm-relaunch', // powershell … irm … .tld/ … powershell
  '0b9ru9l': 'pcalua', // pcalua … curl|powershell|saps|cmd
  '1cnosgc': 'cmdkey-schtasks', // ^cmd … cmdkey … schtasks
  '0bip3qb': 'invoke-command-base64', // ^Invoke-Command … Base64String
  '1w111mb': 'conhost-headless', // ^c(onhost|md) … --headless
  '11o8yiv': 'iex-download', // ^iex(i(rm|wr)
  '1a636xm': 'irm-iex', // ^(irm … iex
  '0iogkr8': 'comspec-start-min', // ^%COMSPEC% … start … /min
  '0e7wa01': 'cmd-temp-bat', // ^cmd … /c … %TEMP% … .bat
  '1i4w3pz': 'cmd-cmdcmdline', // ^cmd … /c … CMDCMDLINE
  '1omfm0t': 'cmd-delayed-expansion', // ^cmd /v:on /q /c
  '1ikrqfe': 'convert-comspec', // convert … $env:ComSpec
  '122w4rr': 'ps-comment-lure', // ^<#Verification
  '1ggbzep': 'iwr-wscript', // ^Invoke-WebRequest … wscript
  '1ocv57d': 'url-filename-exe', // ^$url … \n$filename … .exe
};

/**
 * uBO's excludeMatches of the same filter: text it never blocks (licence
 * headers, JSON, URLs, git/import/require/use lines). Mirrored as an
 * allow-list for 'medium' verdicts only; 'high' shapes are blocked anyway.
 */
const R_UBO_EXCLUDE = /Maintainer|Contributor|^\{|^http|^(git|import|require|use) /i;

/** Names of every rule that matches (tests and diagnostics; the verdict uses the first). */
export function matchingRules(text: string): string[] {
  const f = commandForms(text);
  const out: string[] = [];
  for (const r of RULES) {
    try {
      if (r.test(f)) out.push(r.rule);
    } catch {
      // a rule that throws does not match
    }
  }
  return out;
}

/**
 * The verdict for a clipboard payload, or null when it does not look like a
 * dangerous command. Never throws.
 */
export function detectDangerousCommand(text: unknown): ClipVerdict | null {
  if (typeof text !== 'string' || text.length < 6) return null;
  let f: Forms;
  try {
    f = commandForms(text);
  } catch {
    return null;
  }
  const s = f.s;
  for (const r of RULES) {
    let matched = false;
    try {
      matched = r.test(f);
    } catch {
      matched = false;
    }
    if (!matched) continue;
    if (r.severity === 'medium' && (R_IP_URL.test(s) || R_HTTP_URL.test(s) || R_INSECURE.test(s))) {
      // Scripts from a raw IP, over plain http or with TLS checks off: no install doc does that.
      return { severity: 'high', rule: `${r.rule}-insecure` };
    }
    if (r.severity === 'medium' && R_UBO_EXCLUDE.test(text.trim())) return null;
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
