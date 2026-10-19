# Bastion Shield - writes the extension's managed configuration (chrome.storage.managed)
# into the 3rdparty policy keys of Microsoft Edge, Google Chrome and Brave.
# Intune: platform script, Win32 app or Remediation (see docs/DEPLOYMENT-INTUNE.md).
# Default mode: Apply. Detect-BastionShieldPolicy.ps1 is this script with default mode Detect.
#
# SPDX-License-Identifier: GPL-3.0-or-later

<#
.SYNOPSIS
    Applies, checks or removes the Bastion Shield managed configuration in the registry.

.DESCRIPTION
    Chromium-based browsers read an extension's managed configuration from
        <browser policy key>\3rdparty\extensions\<extension id>\policy
    Edge:   HKLM\SOFTWARE\Policies\Microsoft\Edge\...
    Chrome: HKLM\SOFTWARE\Policies\Google\Chrome\...
    Brave:  HKLM\SOFTWARE\Policies\BraveSoftware\Brave\...

    Intune cannot set these values from the Settings Catalog, and custom ADMX
    ingestion is not allowed to write below Software\Policies\Microsoft, so this
    script writes them directly. It is idempotent: values that are not in the
    configuration are removed, values that already match are left untouched.

    The configuration is taken from (first match wins):
      1. -ConfigPath <file.json>
      2. bastion-shield-policy.json next to this script
      3. the $EmbeddedConfig block below (used by Intune platform scripts and
         Remediations, which upload a single file)

    Encoding: booleans and integers as REG_DWORD, strings as REG_SZ, lists and
    objects as one REG_SZ JSON string (Chromium accepts JSON strings for list and
    dictionary values, and the order of filters is preserved).

    Modes:
      Apply  (default) write the configuration
      Detect exit 0 and print one line when every browser is compliant, exit 1
             otherwise. Works as an Intune Remediation detection script and as
             a Win32 app custom detection script.
      Remove delete the policy keys this script manages (rollback)

.PARAMETER Mode
    Apply, Detect or Remove.

.PARAMETER ConfigPath
    JSON file with "extensionIds" and "policy" (see bastion-shield-policy.example.json).

.PARAMETER Browser
    Limit to Edge, Chrome and/or Brave. Browsers whose id is missing or still a
    placeholder are skipped with a warning.

.PARAMETER Scope
    Machine (HKLM, default; needs SYSTEM or administrator) or User (HKCU).

.PARAMETER TestRoot
    Testing only: write below HKCU\<TestRoot>\<Browser>\... instead of the
    browser policy keys.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BastionShieldPolicy.ps1

.EXAMPLE
    .\Set-BastionShieldPolicy.ps1 -Mode Detect -Browser Edge

.NOTES
    Keep this file ASCII-only: Windows PowerShell 5.1 reads files without a BOM
    as ANSI. Log: %ProgramData%\BastionShield\Logs\BastionShieldPolicy.log
    (Scope User: %LOCALAPPDATA%\BastionShield\Logs).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Apply', 'Detect', 'Remove')]
    [string]$Mode = 'Apply',

    [string]$ConfigPath,

    [ValidateSet('Edge', 'Chrome', 'Brave')]
    [string[]]$Browser = @('Edge', 'Chrome', 'Brave'),

    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine',

    [string]$TestRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration. Replace the placeholders with the store ids of the published
# extension: Chrome and Brave install from the Chrome Web Store, Edge from
# Edge Add-ons, and the two stores assign different ids.
# ---------------------------------------------------------------------------
$EmbeddedConfig = @'
{
  "extensionIds": {
    "edge": "<EDGE_ADDONS_ID>",
    "chrome": "<CHROME_WEB_STORE_ID>",
    "brave": "<CHROME_WEB_STORE_ID>"
  },
  "policy": {
    "organizationName": "Muster AG",
    "supportUrl": "https://intranet.example.com/it-support",
    "supportEmail": "it-support@example.com",
    "reportBrokenSite": "email",
    "disabledSites": ["intranet.example.com", "erp.example.com"],
    "lists": { "annoyances": true },
    "lockSettings": true,
    "historyRetentionDays": 14,
    "protectionEnabled": true
  }
}
'@

# Mirror of policy/managed_schema.json (CI checks that both stay in sync).
# bool / int:<min>:<max> / string / enum:<a,b> / string[] / map-bool
$PolicySchema = [ordered]@{
    organizationName         = 'string'
    supportUrl               = 'string'
    supportEmail             = 'string'
    defaultMode              = 'enum:standard,aggressive'
    lists                    = 'map-bool'
    lockLists                = 'bool'
    disabledSites            = 'string[]'
    aggressiveSites          = 'string[]'
    customFilters            = 'string[]'
    allowUserSiteToggle      = 'bool'
    allowUserFilters         = 'bool'
    lockSettings             = 'bool'
    gpc                      = 'bool'
    stripParams              = 'bool'
    debounce                 = 'bool'
    deAmp                    = 'bool'
    fingerprinting           = 'enum:off,standard,strict'
    blockHyperlinkAuditing   = 'bool'
    webrtcPolicy             = 'enum:default,default_public_interface_only,disable_non_proxied_udp'
    blockThirdPartyCookies   = 'bool'
    disablePrivacySandboxAds = 'bool'
    showBadge                = 'bool'
    activityLog              = 'bool'
    showIncidentCta          = 'bool'
    historyEnabled           = 'bool'
    historyRetentionDays     = 'int:0:3650'
    reportBrokenSite         = 'enum:github,email,none'
    protectionEnabled        = 'bool'
}

$BrowserRoots = [ordered]@{
    Edge   = 'SOFTWARE\Policies\Microsoft\Edge'
    Chrome = 'SOFTWARE\Policies\Google\Chrome'
    Brave  = 'SOFTWARE\Policies\BraveSoftware\Brave'
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
$script:LogFile = $null
function Initialize-Log {
    try {
        if ($Scope -eq 'Machine') { $base = $env:ProgramData } else { $base = $env:LOCALAPPDATA }
        if (-not $base) { return }
        $dir = Join-Path $base 'BastionShield\Logs'
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
        $script:LogFile = Join-Path $dir 'BastionShieldPolicy.log'
        # Keep the log small: start over above 1 MB.
        if ((Test-Path -LiteralPath $script:LogFile) -and ((Get-Item -LiteralPath $script:LogFile).Length -gt 1MB)) {
            Remove-Item -LiteralPath $script:LogFile -Force -WhatIf:$false
        }
    } catch {
        $script:LogFile = $null
    }
}

function Write-BsLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Mode, $Message
    if ($script:LogFile) {
        # Logging must never stop the script; give up on the file after the first failure.
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false } catch { $script:LogFile = $null }
    }
    # Detect mode prints exactly one summary line on stdout (Intune shows it).
    if ($Mode -ne 'Detect') {
        if ($Level -eq 'ERROR') { [Console]::Error.WriteLine($line) }
        elseif ($Level -eq 'WARN') { Write-Warning $Message }
        else { Write-Host $line }
    } elseif ($Level -ne 'INFO') {
        [Console]::Error.WriteLine($line)
    }
}

# ---------------------------------------------------------------------------
# Configuration loading and validation
# ---------------------------------------------------------------------------
function Get-ConfigText {
    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config file not found: $ConfigPath" }
        Write-BsLog "Using configuration file $ConfigPath"
        return [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $ConfigPath).ProviderPath)
    }
    if ($PSScriptRoot) {
        $side = Join-Path $PSScriptRoot 'bastion-shield-policy.json'
        if (Test-Path -LiteralPath $side) {
            Write-BsLog "Using configuration file $side"
            return [System.IO.File]::ReadAllText($side)
        }
    }
    Write-BsLog 'Using the embedded configuration'
    return $EmbeddedConfig
}

function Test-IsInteger($v) {
    return ($v -is [int]) -or ($v -is [long]) -or ($v -is [int16]) -or ($v -is [byte])
}

function ConvertTo-CompactJson($Value) {
    # -InputObject keeps one-element arrays as arrays (the pipeline would unroll them).
    return (ConvertTo-Json -InputObject $Value -Compress -Depth 10)
}

function Get-DesiredPolicyValue {
    # Validates the policy object and returns name -> @{ Kind; Data } in registry form.
    param($Policy)
    $problems = New-Object System.Collections.Generic.List[string]
    $desired = [ordered]@{}
    if ($null -eq $Policy) { return @{ Values = $desired; Problems = $problems } }
    if ($Policy -isnot [System.Management.Automation.PSCustomObject]) {
        $problems.Add('"policy" must be a JSON object')
        return @{ Values = $desired; Problems = $problems }
    }
    foreach ($prop in $Policy.PSObject.Properties) {
        $name = $prop.Name
        $value = $prop.Value
        # [ordered] dictionaries compare keys case-insensitively; insist on the
        # exact spelling so the same JSON also works in macOS profiles.
        $canonical = @($PolicySchema.Keys | Where-Object { $_ -ceq $name })
        if ($canonical.Count -eq 0) {
            $near = @($PolicySchema.Keys | Where-Object { $_ -eq $name })
            if ($near.Count -gt 0) { $problems.Add("policy key '$name' must be spelled '$($near[0])'") }
            else { $problems.Add("unknown policy key '$name' (see policy/managed_schema.json)") }
            continue
        }
        $type = $PolicySchema[$name]
        if ($type -eq 'bool') {
            if ($value -isnot [bool]) { $problems.Add("$name must be true or false"); continue }
            $desired[$name] = @{ Kind = 'DWord'; Data = [int]$value }
        } elseif ($type.StartsWith('int:')) {
            $parts = $type.Split(':')
            if (-not (Test-IsInteger $value)) { $problems.Add("$name must be an integer"); continue }
            if ($value -lt [long]$parts[1] -or $value -gt [long]$parts[2]) { $problems.Add("$name must be between $($parts[1]) and $($parts[2])"); continue }
            $desired[$name] = @{ Kind = 'DWord'; Data = [int]$value }
        } elseif ($type -eq 'string') {
            if ($value -isnot [string]) { $problems.Add("$name must be a string"); continue }
            $desired[$name] = @{ Kind = 'String'; Data = $value }
        } elseif ($type.StartsWith('enum:')) {
            $allowed = $type.Substring(5).Split(',')
            if (($value -isnot [string]) -or ($allowed -cnotcontains $value)) { $problems.Add("$name must be one of: $($allowed -join ', ')"); continue }
            $desired[$name] = @{ Kind = 'String'; Data = $value }
        } elseif ($type -eq 'string[]') {
            if ($value -isnot [System.Array]) { $problems.Add("$name must be a JSON array of strings"); continue }
            $bad = @($value | Where-Object { $_ -isnot [string] })
            if ($bad.Count -gt 0) { $problems.Add("$name must contain strings only"); continue }
            if ($name -eq 'disabledSites' -or $name -eq 'aggressiveSites') {
                foreach ($h in $value) {
                    if ($h -cnotmatch '^[a-z0-9.-]+$' -or $h.StartsWith('.') -or $h.EndsWith('.')) {
                        $problems.Add("${name}: '$h' is not a plain lower-case hostname (no scheme, path, port or wildcard)")
                    }
                }
            }
            $desired[$name] = @{ Kind = 'String'; Data = (ConvertTo-CompactJson ([object[]]$value)) }
        } elseif ($type -eq 'map-bool') {
            if ($value -isnot [System.Management.Automation.PSCustomObject]) { $problems.Add("$name must be a JSON object such as { `"annoyances`": true }"); continue }
            $ok = $true
            foreach ($entry in $value.PSObject.Properties) {
                if ($entry.Value -isnot [bool]) { $problems.Add("$name.$($entry.Name) must be true or false"); $ok = $false }
                if ($entry.Name -cnotmatch '^[a-z0-9-]+$') { $problems.Add("$name.$($entry.Name) is not a valid list id"); $ok = $false }
            }
            if ($ok) { $desired[$name] = @{ Kind = 'String'; Data = (ConvertTo-CompactJson $value) } }
        }
    }
    return @{ Values = $desired; Problems = $problems }
}

function Get-NormalizedJson([string]$Text) {
    # Round-trip so that apply (PowerShell 7) and detect (Windows PowerShell 5.1)
    # compare equal even though their JSON escaping differs.
    try { return (ConvertTo-CompactJson (ConvertFrom-Json -InputObject $Text)) } catch { return $Text }
}

# ---------------------------------------------------------------------------
# Registry helpers (always the 64-bit view: Intune runs scripts in a 32-bit
# host by default, which would otherwise write to WOW6432Node)
# ---------------------------------------------------------------------------
function Get-BaseKey {
    if ($Scope -eq 'Machine' -and -not $TestRoot) { $hive = [Microsoft.Win32.RegistryHive]::LocalMachine }
    else { $hive = [Microsoft.Win32.RegistryHive]::CurrentUser }
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-ExtensionKeyPath([string]$Name, [string]$Id) {
    if ($TestRoot) { return ('{0}\{1}\3rdparty\extensions\{2}' -f $TestRoot.Trim('\'), $Name, $Id) }
    return ('{0}\3rdparty\extensions\{1}' -f $BrowserRoots[$Name], $Id)
}

function Test-ValueMatch($Key, [string]$Name, $Want) {
    if ($Key.GetValueNames() -notcontains $Name) { return $false }
    $kind = $Key.GetValueKind($Name)
    $data = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($Want.Kind -eq 'DWord') {
        return ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) -and ([int]$data -eq [int]$Want.Data)
    }
    if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String) { return $false }
    if ([string]$data -ceq [string]$Want.Data) { return $true }
    $w = [string]$Want.Data
    if ($w.StartsWith('[') -or $w.StartsWith('{')) { return (Get-NormalizedJson ([string]$data)) -ceq (Get-NormalizedJson $w) }
    return $false
}

function Invoke-Apply([string]$Name, [string]$Id, $Desired) {
    $base = Get-BaseKey
    try {
        $path = (Get-ExtensionKeyPath $Name $Id) + '\policy'
        if ($Desired.Count -eq 0) {
            Write-BsLog "${Name}: configuration is empty, removing $path"
            Invoke-Remove $Name $Id
            return
        }
        if (-not $PSCmdlet.ShouldProcess($path, 'Write Bastion Shield policy')) { return }
        $key = $base.CreateSubKey($path, $true)
        if ($null -eq $key) { throw "Cannot open or create $path" }
        try {
            $changes = 0
            # Sub-keys are an alternative encoding (for example from a .reg import);
            # Chromium would merge them with our values, so they must go.
            foreach ($sub in $key.GetSubKeyNames()) {
                $key.DeleteSubKeyTree($sub)
                Write-BsLog "${Name}: removed sub-key policy\$sub"
                $changes++
            }
            foreach ($existing in $key.GetValueNames()) {
                if (-not $Desired.Contains($existing)) {
                    $key.DeleteValue($existing)
                    Write-BsLog "${Name}: removed value $existing"
                    $changes++
                }
            }
            foreach ($valueName in $Desired.Keys) {
                $want = $Desired[$valueName]
                if (Test-ValueMatch $key $valueName $want) { continue }
                if ($want.Kind -eq 'DWord') { $key.SetValue($valueName, [int]$want.Data, [Microsoft.Win32.RegistryValueKind]::DWord) }
                else { $key.SetValue($valueName, [string]$want.Data, [Microsoft.Win32.RegistryValueKind]::String) }
                Write-BsLog "${Name}: set $valueName"
                $changes++
            }
            Write-BsLog ("{0}: {1} ({2} change(s))" -f $Name, $path, $changes)
        } finally {
            $key.Close()
        }
    } finally {
        $base.Close()
    }
}

function Invoke-Remove([string]$Name, [string]$Id) {
    $base = Get-BaseKey
    try {
        $extPath = Get-ExtensionKeyPath $Name $Id
        $ext = $base.OpenSubKey($extPath, $true)
        if ($null -eq $ext) { Write-BsLog "${Name}: nothing to remove"; return }
        try {
            if ($ext.GetSubKeyNames() -contains 'policy') {
                if ($PSCmdlet.ShouldProcess("$extPath\policy", 'Delete Bastion Shield policy')) {
                    $ext.DeleteSubKeyTree('policy')
                    Write-BsLog "${Name}: removed $extPath\policy"
                }
            }
            $empty = ($ext.GetSubKeyNames().Count -eq 0) -and ($ext.GetValueNames().Count -eq 0)
        } finally {
            $ext.Close()
        }
        # Leave the extension key alone if something else (for example a
        # "recommended" key) still lives there.
        if ($empty -and $PSCmdlet.ShouldProcess($extPath, 'Delete empty key')) { $base.DeleteSubKey($extPath, $false) }
    } finally {
        $base.Close()
    }
}

function Test-Compliant([string]$Name, [string]$Id, $Desired) {
    $base = Get-BaseKey
    try {
        $path = (Get-ExtensionKeyPath $Name $Id) + '\policy'
        $key = $base.OpenSubKey($path, $false)
        if ($Desired.Count -eq 0) {
            if ($null -ne $key) { $key.Close(); return "$Name has policy values but none are configured" }
            return $null
        }
        if ($null -eq $key) { return "$Name policy key missing" }
        try {
            if ($key.GetSubKeyNames().Count -gt 0) { return "$Name has unexpected sub-keys" }
            foreach ($existing in $key.GetValueNames()) {
                if (-not $Desired.Contains($existing)) { return "$Name has extra value $existing" }
            }
            foreach ($valueName in $Desired.Keys) {
                if (-not (Test-ValueMatch $key $valueName $Desired[$valueName])) { return "$Name value $valueName differs" }
            }
            return $null
        } finally {
            $key.Close()
        }
    } finally {
        $base.Close()
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Initialize-Log
try {
    $config = ConvertFrom-Json -InputObject (Get-ConfigText)
    if ($null -eq $config -or $config -isnot [System.Management.Automation.PSCustomObject]) { throw 'The configuration must be a JSON object.' }
    $ids = $null
    if ($config.PSObject.Properties.Name -contains 'extensionIds') { $ids = $config.extensionIds }
    if ($null -eq $ids) { throw 'The configuration has no "extensionIds" object.' }
    $policy = $null
    if ($config.PSObject.Properties.Name -contains 'policy') { $policy = $config.policy }

    $result = Get-DesiredPolicyValue $policy
    if ($result.Problems.Count -gt 0) {
        foreach ($p in $result.Problems) { Write-BsLog $p 'ERROR' }
        throw ('Invalid configuration ({0} problem(s)); nothing was changed.' -f $result.Problems.Count)
    }
    $desired = $result.Values

    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($name in $Browser) {
        $idProp = $ids.PSObject.Properties | Where-Object { $_.Name -eq $name.ToLowerInvariant() }
        $id = $null
        if ($idProp) { $id = [string]$idProp.Value }
        if (-not $id -or $id -cnotmatch '^[a-p]{32}$') {
            Write-BsLog ("{0}: skipped, extensionIds.{1} is missing or not a 32-letter id ('{2}')" -f $name, $name.ToLowerInvariant(), $id) 'WARN'
            continue
        }
        $targets.Add(@{ Name = $name; Id = $id })
    }
    if ($targets.Count -eq 0) { throw 'No browser with a valid extension id; replace the <..._ID> placeholders.' }

    if ($Mode -eq 'Detect') {
        $issues = @()
        foreach ($t in $targets) {
            $issue = Test-Compliant $t.Name $t.Id $desired
            if ($issue) { $issues += $issue }
        }
        if ($issues.Count -gt 0) {
            Write-BsLog ('Not compliant: ' + ($issues -join '; '))
            Write-Output ('Bastion Shield policy not compliant: ' + ($issues -join '; '))
            exit 1
        }
        $names = ($targets | ForEach-Object { $_.Name }) -join ', '
        Write-BsLog "Compliant: $names"
        Write-Output "Bastion Shield policy compliant: $names"
        exit 0
    }

    foreach ($t in $targets) {
        if ($Mode -eq 'Remove') { Invoke-Remove $t.Name $t.Id }
        else { Invoke-Apply $t.Name $t.Id $desired }
    }
    Write-BsLog 'Done. Browsers pick up the change within about 15 minutes, or at once via "Reload policies" on edge://policy / chrome://policy.'
    exit 0
} catch {
    Write-BsLog $_.Exception.Message 'ERROR'
    if ($Mode -eq 'Detect') { Write-Output ('Bastion Shield policy check failed: ' + $_.Exception.Message) }
    exit 1
}
