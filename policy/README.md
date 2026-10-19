# Bastion Shield policy kit

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

Files for administrators who deploy Bastion Shield centrally (Microsoft Intune, Group Policy, macOS MDM). The step-by-step guide is [docs/DEPLOYMENT-INTUNE.md](../docs/DEPLOYMENT-INTUNE.md).

## Extension ids

All examples use placeholders. Replace them before use:

| Placeholder | Meaning | Used by |
|---|---|---|
| `<CHROME_WEB_STORE_ID>` | id of Bastion Shield in the Chrome Web Store | Google Chrome, Brave |
| `<EDGE_ADDONS_ID>` | id of Bastion Shield in Microsoft Edge Add-ons | Microsoft Edge |

The two stores assign **different** ids. In the `.mobileconfig` files the placeholders are written without angle brackets (`CHROME_WEB_STORE_ID`, `EDGE_ADDONS_ID`) because `<` is not allowed in XML text. The scripts refuse to write anything for a browser whose id is still a placeholder.

## Files

| File | Purpose |
|---|---|
| [`managed_schema.json`](managed_schema.json) | The `chrome.storage.managed` schema shipped inside the extension (`storage.managed_schema`). It defines every key an administrator can set. It mirrors `ManagedPolicy` in `src/shared/types.ts`; CI (`.github/scripts/check-policy.ts`) checks both, and checks the schema against the subset Chromium accepts, because an invalid schema stops the extension from loading. |
| [`examples/intune-settings-catalog.md`](examples/intune-settings-catalog.md) | Which Intune Settings Catalog entries to create, with values. |
| [`examples/edge-extensionsettings.reg`](examples/edge-extensionsettings.reg) | Force-install in Edge (registry, for a test machine). |
| [`examples/chrome-extensionsettings.reg`](examples/chrome-extensionsettings.reg) | Force-install in Chrome. |
| [`examples/brave-extensionsettings.reg`](examples/brave-extensionsettings.reg) | Force-install in Brave. |
| [`examples/bastion-shield-policy-edge.reg`](examples/bastion-shield-policy-edge.reg) | Example extension configuration for Edge (`3rdparty` policy key), showing every registry encoding. |
| [`examples/bastion-shield-policy-chrome.reg`](examples/bastion-shield-policy-chrome.reg) | The same for Chrome. |
| [`examples/bastion-shield-policy-brave.reg`](examples/bastion-shield-policy-brave.reg) | The same for Brave. |
| [`examples/Set-BastionShieldPolicy.ps1`](examples/Set-BastionShieldPolicy.ps1) | Writes the extension configuration for Edge, Chrome and Brave from a JSON document; idempotent; `-Mode Apply`, `Detect` or `Remove`. For Intune Remediations, Win32 apps and platform scripts. |
| [`examples/Detect-BastionShieldPolicy.ps1`](examples/Detect-BastionShieldPolicy.ps1) | The same script with `Detect` as default mode, for use as an Intune detection script. Keep both files identical apart from the mode line, and paste the same configuration into both. |
| [`examples/bastion-shield-policy.example.json`](examples/bastion-shield-policy.example.json) | Example input for the script. |
| [`examples/com.microsoft.Edge.mobileconfig`](examples/com.microsoft.Edge.mobileconfig) | macOS configuration profile: force-install in Edge and the extension configuration. |
| [`examples/com.google.Chrome.mobileconfig`](examples/com.google.Chrome.mobileconfig) | The same for Chrome on macOS. |

## Policy keys at a glance

Every key is optional; a key that is set overrides the user's choice and locks the control. Full table with defaults: [DEPLOYMENT-INTUNE.md, section 4.2](../docs/DEPLOYMENT-INTUNE.md#42-keys).

`organizationName`, `supportUrl`, `supportEmail`, `reportBrokenSite`, `defaultMode`, `aggressiveSites`, `disabledSites`, `allowUserSiteToggle`, `lists`, `lockLists`, `customFilters`, `allowUserFilters`, `allowCustomLists`, `lockSettings`, `gpc`, `stripParams`, `debounce`, `deAmp`, `fingerprinting`, `blockHyperlinkAuditing`, `disablePrivacySandboxAds`, `webrtcPolicy`, `blockThirdPartyCookies`, `showBadge`, `activityLog`, `showIncidentCta`, `historyEnabled`, `historyRetentionDays`, `protectionEnabled` (emergency switch: `false` turns protection off everywhere).

`lockSettings: true` also locks the filter lists, the per-site mode, script and fingerprinting settings, the user filter editor and imported lists, unless `lockLists` is explicitly `false`, `allowUserFilters` or `allowCustomLists` explicitly `true`. If `supportEmail` is set and `reportBrokenSite` is not, "Report a broken site" opens an e-mail to that address.

## Changing the schema

1. Change `ManagedPolicy` in `src/shared/types.ts` (architecture contract) and the code that reads it.
2. Update `managed_schema.json`. Use only keywords Chromium supports: `type`, `properties`, `additionalProperties`, `patternProperties`, `items`, `enum` (string and integer only), `minimum`/`maximum` (integer only), `pattern` (string only, not combined with `enum`), `required`, `id`, `$ref`, `title`, `description`. The top level must be `"type": "object"` without `additionalProperties`.
3. Update `$PolicySchema` in both PowerShell scripts, the examples and the key table in the deployment guide.
4. Run `node .github/scripts/check-policy.ts`. On Windows, also run `pwsh -File .github/scripts/test-policy-script.ps1`.

Removing or renaming a key breaks existing customer configurations silently (Chromium drops unknown keys). Add new keys instead, and keep old ones working for at least one major version.
