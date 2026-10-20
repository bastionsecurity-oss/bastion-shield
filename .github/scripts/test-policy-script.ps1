# Functional test for policy/examples/Set-BastionShieldPolicy.ps1 on Windows:
# apply, detect, drift repair, invalid input and removal, against a throwaway
# HKCU test key (-TestRoot) so nothing touches real browser policy.
# Run: pwsh -File .github/scripts/test-policy-script.ps1 [-Shell powershell.exe]
#
# SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
# SPDX-License-Identifier: GPL-3.0-or-later

param(
    # Host that runs the script under test: pwsh (PowerShell 7) or powershell.exe (5.1).
    [string]$Shell = 'pwsh'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$set = Join-Path $root 'policy\examples\Set-BastionShieldPolicy.ps1'
$detect = Join-Path $root 'policy\examples\Detect-BastionShieldPolicy.ps1'
$testRoot = 'Software\BastionShieldPolicyCiTest'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('bs-policy-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$failures = 0

function Invoke-Script([string]$Path, [string[]]$Arguments) {
    $common = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Path)
    if ($Shell -eq 'pwsh') { $common = @('-NoProfile', '-File', $Path) }
    $out = & $Shell @common @Arguments '-Scope' 'User' '-TestRoot' $testRoot 2>&1
    return @{ Code = $LASTEXITCODE; Output = ($out | Out-String) }
}

function Assert([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "ok   $Message" }
    else { Write-Host "FAIL $Message"; $script:failures++ }
}

$edgeId = 'abcdefghijklmnopabcdefghijklmnop'
$chromeId = 'bcdefghijklmnopabcdefghijklmnopa'
$config = @{
    extensionIds = @{ edge = $edgeId; chrome = $chromeId; brave = '<CHROME_WEB_STORE_ID>' }
    policy       = [ordered]@{
        organizationName     = 'Muster AG'
        disabledSites        = @('intranet.example.com')
        customFilters        = @("||ads.example.net^`$third-party", "example.com##div[data-x='a<b>&c']")
        lists                = @{ annoyances = $true }
        lockSettings         = $true
        historyRetentionDays = 14
        fingerprinting       = 'strict'
    }
}
$cfg = Join-Path $work 'cfg.json'
$config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $cfg -Encoding UTF8
$bad = Join-Path $work 'bad.json'
'{ "extensionIds": { "edge": "' + $edgeId + '" }, "policy": { "OrganizationName": "x", "gpc": "yes", "disabledSites": ["https://a.example/"] } }' | Set-Content -LiteralPath $bad -Encoding UTF8

try {
    $r = Invoke-Script $detect @('-ConfigPath', $cfg)
    Assert ($r.Code -eq 1) 'detect reports non-compliance before apply'

    $r = Invoke-Script $set @('-ConfigPath', $cfg)
    Assert ($r.Code -eq 0) 'apply succeeds'
    $edgeKey = "HKCU:\$testRoot\Edge\3rdparty\extensions\$edgeId\policy"
    $values = Get-ItemProperty -LiteralPath $edgeKey
    Assert ($values.organizationName -eq 'Muster AG') 'string written as REG_SZ'
    Assert ($values.lockSettings -eq 1) 'boolean written as REG_DWORD 1'
    Assert ($values.historyRetentionDays -eq 14) 'integer written as REG_DWORD'
    Assert ($values.disabledSites -eq '["intranet.example.com"]') 'one-element list stays a JSON array'
    Assert ($values.lists -eq '{"annoyances":true}') 'object written as JSON string'
    Assert (-not (Test-Path "HKCU:\$testRoot\Brave")) 'browser with placeholder id is skipped'

    $r = Invoke-Script $detect @('-ConfigPath', $cfg)
    Assert ($r.Code -eq 0 -and $r.Output -match 'compliant: Edge, Chrome') 'detect reports compliance after apply'

    $r = Invoke-Script $set @('-ConfigPath', $cfg)
    Assert ($r.Output -match '\(0 change\(s\)\)') 'second apply changes nothing'

    New-ItemProperty -LiteralPath $edgeKey -Name gpc -PropertyType DWord -Value 0 -Force | Out-Null
    New-Item -Path "$edgeKey\disabledSites" -Force | Out-Null
    $r = Invoke-Script $detect @('-ConfigPath', $cfg)
    Assert ($r.Code -eq 1) 'detect notices an extra value and sub-key'
    $r = Invoke-Script $set @('-ConfigPath', $cfg)
    $r2 = Invoke-Script $detect @('-ConfigPath', $cfg)
    Assert ($r.Code -eq 0 -and $r2.Code -eq 0) 'apply repairs drift'

    $before = (Get-ItemProperty -LiteralPath $edgeKey).organizationName
    $r = Invoke-Script $set @('-ConfigPath', $bad)
    Assert ($r.Code -eq 1) 'invalid configuration is rejected'
    Assert ($r.Output -match "must be spelled 'organizationName'" -and $r.Output -match 'gpc must be true or false') 'problems are reported'
    Assert ((Get-ItemProperty -LiteralPath $edgeKey).organizationName -eq $before) 'invalid configuration changes nothing'

    $r = Invoke-Script $set @('-Mode', 'Remove', '-ConfigPath', $cfg)
    Assert ($r.Code -eq 0 -and -not (Test-Path -LiteralPath $edgeKey)) 'remove deletes the policy key'
} finally {
    if (Test-Path "HKCU:\$testRoot") { Remove-Item -Recurse -Force "HKCU:\$testRoot" }
    Remove-Item -Recurse -Force $work
}

if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host 'All policy script checks passed.'
