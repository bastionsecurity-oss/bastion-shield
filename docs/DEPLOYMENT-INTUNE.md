# Deploying Bastion Shield with Microsoft Intune

How to install Bastion Shield on managed Windows and macOS devices in Microsoft Edge, Google Chrome and Brave, configure it centrally, verify it and roll it back. Written for Intune administrators at Bastion and at customers.

## Kurzfassung (Deutsch)

- **Installation:** Bastion Shield wird über die Browser-Richtlinie `ExtensionSettings` als Pflicht-Erweiterung installiert («force_installed»). Für Edge und Chrome unter Windows geht das im Intune-Einstellungskatalog, für Edge unter macOS ebenfalls; Chrome unter macOS und Brave brauchen ein Konfigurationsprofil, einen importierten ADMX-Satz oder ein Skript. Benutzer können die Erweiterung danach weder entfernen noch deaktivieren.
- **Zwei IDs:** Chrome Web Store und Edge Add-ons vergeben **unterschiedliche Erweiterungs-IDs**. Chrome und Brave verwenden die Chrome-Web-Store-ID, Edge die Edge-Add-ons-ID.
- **Konfiguration:** Die Einstellungen der Erweiterung (z. B. Organisationsname, ausgenommene Websites, gesperrte Einstellungen) liegen unter `…\3rdparty\extensions\<ID>\policy`. Intune bietet dafür keinen Katalogeintrag. Wir liefern das idempotente Skript `policy/examples/Set-BastionShieldPolicy.ps1` (Plattformskript, Win32-App oder Remediation) und Beispiel-Profile für macOS.
- **Kontrolle:** `edge://policy`, `chrome://policy` bzw. `brave://policy` und im Bastion-Shield-Dashboard der Hinweis «Verwaltet von …».
- **Nichts verlässt das Gerät:** Bastion Shield sendet keine Telemetrie. Updates der Filterlisten kommen wöchentlich als neue Version über den Store.
- **Brave:** Brave Shields blockiert bereits vor jeder Erweiterung. Auf Brave ist Bastion Shield deshalb nur eine Ergänzung (siehe [FAQ](#faq)).
- **Notfall:** `"protectionEnabled": false` schaltet den Schutz auf allen zugewiesenen Geräten aus, ohne die Erweiterung zu entfernen. `true` oder das Entfernen des Schlüssels stellt ihn wieder her ([Abschnitt 9](#9-emergency-switch-protection-off-fleet-wide)).

---

## Contents

1. [Overview and choices](#1-overview-and-choices)
2. [Before you start](#2-before-you-start)
3. [Step 1: force-install the extension](#3-step-1-force-install-the-extension)
4. [Step 2: configure Bastion Shield (managed storage)](#4-step-2-configure-bastion-shield-managed-storage)
5. [Step 3: verify](#5-step-3-verify)
6. [Complementary browser policies](#6-complementary-browser-policies)
7. [Self-hosting the extension (advanced)](#7-self-hosting-the-extension-advanced)
8. [Rollout, updates and rollback](#8-rollout-updates-and-rollback)
9. [Emergency: switch protection off fleet-wide](#9-emergency-switch-protection-off-fleet-wide)
10. [FAQ](#faq)

Ready-made files are in [`policy/`](../policy/README.md). The settings to click through are summarised in [`policy/examples/intune-settings-catalog.md`](../policy/examples/intune-settings-catalog.md).

---

## 1. Overview and choices

A deployment has two independent parts:

| Part | What it does | How |
|---|---|---|
| **Install** | The browser installs Bastion Shield silently, keeps it updated and prevents removal. | Browser policy `ExtensionSettings` (or the older `ExtensionInstallForcelist`). |
| **Configure** (optional) | Organisation name, sites with protection off, locked settings, extra filter lists, admin filters. | Extension policy read through `chrome.storage.managed`, stored under `<browser policy key>\3rdparty\extensions\<id>\policy`. |

Bastion Shield works without any configuration: a plain force-install gives every user Brave-equivalent protection with the defaults described in [FILTER-LISTS.md](FILTER-LISTS.md). When the policy sets `organizationName`, the first-run welcome page stays closed.

### Store-hosted (recommended) or self-hosted

| | Chrome Web Store + Edge Add-ons (recommended) | Self-hosted CRX |
|---|---|---|
| Works on | every device, including BYOD and unmanaged | only devices the browser treats as managed (see [section 7](#7-self-hosting-the-extension-advanced)) |
| Extension ids | **different per store**: Chrome/Brave use the Chrome Web Store id, Edge the Edge Add-ons id | one id everywhere |
| Updates | the browser checks about every 5 hours; the store review adds delay (Chrome Web Store: minutes to days; Edge Add-ons: up to 7 business days) | as soon as Bastion publishes; the browser picks it up at its next check |
| Operations for Bastion | store accounts only | signing-key custody, an always-on HTTPS server, `update.xml` |

Use the stores unless you have a specific reason not to.

---

## 2. Before you start

- **Extension ids.** Throughout this guide and in `policy/examples/`:
  - `<CHROME_WEB_STORE_ID>`: Bastion Shield in the Chrome Web Store. Used by **Chrome and Brave**.
  - `<EDGE_ADDONS_ID>`: Bastion Shield in Microsoft Edge Add-ons. Used by **Edge**.

  An extension id is 32 letters from `a` to `p`. Copy it from the store listing URL or from `chrome://extensions` / `edge://extensions` (Developer mode shows ids). Never use one store's id with the other store's update URL.
- **Store update URLs** (verbatim, no trailing slash):
  - Chrome Web Store: `https://clients2.google.com/service/update2/crx`
  - Edge Add-ons: `https://edge.microsoft.com/extensionwebstorebase/v1/crx` (some older Microsoft pages still show `https://extensionwebstorebase.edgesv.net/v1/crx`; use the `edge.microsoft.com` URL from the [ExtensionSettings reference guide](https://learn.microsoft.com/deployedge/microsoft-edge-manage-extensions-ref-guide)).
- **Browser versions.** Bastion Shield needs Chromium 128 or newer (`minimum_chrome_version`). Some complementary policies need newer versions; they are noted in [section 6](#6-complementary-browser-policies).
- **Intune role.** Creating Settings Catalog policies needs at least the *Policy and Profile Manager* role ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-edge)).
- **Devices** must be enrolled in Intune. Settings Catalog and custom profiles are device-management features; app protection policies alone cannot install extensions.
- **One `ExtensionSettings` per browser.** `ExtensionSettings` is a single JSON value. If your organisation already sets it (for example to block all other extensions with `"*": {"installation_mode": "blocked"}`), add the Bastion Shield entry to that JSON. Two Intune profiles that both set it conflict.

---

## 3. Step 1: force-install the extension

### 3.1 The `ExtensionSettings` value

Use one JSON per browser. The toolbar key differs: Chrome and Brave use `toolbar_pin`, Edge uses `toolbar_state`.

**Microsoft Edge** ([policy reference](https://learn.microsoft.com/deployedge/microsoft-edge-policies/extensionsettings)):

```json
{"<EDGE_ADDONS_ID>":{"installation_mode":"force_installed","update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx","toolbar_state":"force_shown"}}
```

**Google Chrome and Brave** ([policy reference](https://chromeenterprise.google/policies/#ExtensionSettings)):

```json
{"<CHROME_WEB_STORE_ID>":{"installation_mode":"force_installed","update_url":"https://clients2.google.com/service/update2/crx","toolbar_pin":"force_pinned"}}
```

Field notes:

| Field | Value | Notes |
|---|---|---|
| `installation_mode` | `force_installed` | Installed silently; users cannot remove or disable it. Removing the entry uninstalls the extension. `normal_installed` installs it but lets users disable it. |
| `update_url` | store URL above | Required for `force_installed`. The browser uses it for the first install and the URL in the extension's manifest for later updates ([Edge guide](https://learn.microsoft.com/deployedge/microsoft-edge-manage-extensions-ref-guide)). |
| `toolbar_state` (Edge 103+) | `force_shown`, `default_shown`, `default_hidden` | Edge only. Recommended: `force_shown`, so users see the shield and its blocked count. |
| `toolbar_pin` (Chrome, Brave) | `force_pinned`, `default_pinned`, `default_unpinned` | Chrome only. **Do not put `toolbar_state` into the Chrome JSON or an unknown `toolbar_pin` value into it**: Chrome validates the whole policy against its schema, and an invalid value for a known key rejects the entire `ExtensionSettings` policy, including all force-installs. |
| `minimum_version_required` | e.g. `"1.0.0.2910"` | The browser **disables** older versions, including force-installed ones, until the update arrives. That turns protection off on those devices for hours. Use it only to stop a version with a security problem. |
| `override_update_url` | `true` | Only for self-hosting (section 7). Ignored when `update_url` is the browser's own store. |
| `runtime_blocked_hosts` | host patterns | Stops an extension from interacting with those sites ("JavaScript injection, cookie access, and web-request modifications", per the [Edge guide](https://learn.microsoft.com/deployedge/microsoft-edge-manage-extensions-ref-guide)). Whether it also stops Bastion Shield's declarative network rules there is **untested**. Do not use it as a "protection off" switch; use `disabledSites` in the extension policy instead (section 4). Note that a per-extension entry inherits only `installation_mode` and `update_url` from the `"*"` entry, so a global `"*": {"runtime_blocked_hosts": [...]}` does not apply to Bastion Shield once it has its own entry. |

`ExtensionInstallForcelist` is the older alternative: one string per extension, `<id>;<update_url>`. It installs the extension the same way but cannot pin it. Microsoft notes that `ExtensionSettings` supersedes the legacy extension policies. Configure one or the other, not both.

Neither policy applies to Incognito or InPrivate windows; see the [FAQ](#faq).

### 3.2 Microsoft Edge on Windows (Settings Catalog)

1. Intune admin center: **Devices > Manage devices > Configuration > Create > New policy**.
2. Platform **Windows 10 and later**, profile type **Settings catalog**, **Create**.
3. Name it, for example `Bastion Shield - Edge - install`.
4. **Add settings**, search `extension management`, open category **Microsoft Edge > Extensions**, select **Configure extension management settings**.
5. Set it to **Enabled** and paste the Edge JSON from 3.1 (one line).
6. Assign to a device group (pilot first; see [section 8](#8-rollout-updates-and-rollback)), **Create**.

Settings without `(User)` in their name apply to the device; settings with `(User)` apply to users ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-edge)). Use the device setting.

### 3.3 Microsoft Edge on macOS

Either:

- **Settings Catalog** (preferred): platform **macOS**, profile type **Settings catalog**, then **Microsoft Edge > Extensions > Configure extension management settings** with the same JSON; or
- **Custom profile**: upload [`policy/examples/com.microsoft.Edge.mobileconfig`](../policy/examples/com.microsoft.Edge.mobileconfig) under **macOS > Templates > Custom**, deployment channel **Device channel** ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/templates/configure-custom-settings-apple)). This profile also carries the extension configuration (section 4.5). If you use it, remove its `com.microsoft.Edge` payload or do not set `ExtensionSettings` in the Settings Catalog as well.

### 3.4 Google Chrome on Windows (Settings Catalog)

Google Chrome settings are built into the Intune Settings Catalog on Windows ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/common-tasks)).

1. **Devices > Manage devices > Configuration > Create > New policy**, platform **Windows 10 and later**, **Settings catalog**.
2. **Add settings**, browse to **Google > Google Chrome > Extensions** and select **Extension management settings** (Chrome's name for `ExtensionSettings`).
3. **Enabled**, paste the Chrome JSON from 3.1.
4. Assign and create.

Alternative in the same category: **Configure the list of force-installed apps and extensions** with the value `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx` (this is how Microsoft documents its own Chrome extension, see [Microsoft Purview](https://learn.microsoft.com/purview/dlp-chrome-get-started)). Display names can differ slightly between catalog versions; search for the policy name if you do not find them.

### 3.5 Google Chrome on macOS

The Settings Catalog has no Chrome settings for macOS. Use either:

- **Custom profile** (recommended): [`policy/examples/com.google.Chrome.mobileconfig`](../policy/examples/com.google.Chrome.mobileconfig), **macOS > Templates > Custom**, **Device channel**. It installs the extension and carries its configuration.
- **Preference file**: **macOS > Templates > Preference file**, preference domain `com.google.Chrome`, with a `.plist` that contains only key/value pairs without `<plist>` or `<dict>` wrappers ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/templates/configure-preference-file-macos)); replace `CHROME_WEB_STORE_ID` with the id:

  ```xml
  <key>ExtensionSettings</key>
  <dict>
    <key>CHROME_WEB_STORE_ID</key>
    <dict>
      <key>installation_mode</key><string>force_installed</string>
      <key>update_url</key><string>https://clients2.google.com/service/update2/crx</string>
      <key>toolbar_pin</key><string>force_pinned</string>
    </dict>
  </dict>
  ```

### 3.6 Brave

Brave "is built on Chromium and supports all of the policies that Chromium does" ([Brave Help Center](https://support.brave.app/hc/en-us/articles/360039248271-Group-Policy)). It installs extensions from the Chrome Web Store, so use the **Chrome** JSON and the Chrome Web Store id. Read the [Brave FAQ entry](#should-we-deploy-bastion-shield-to-brave) first.

- **Windows** policy root: `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. Brave is not in the Intune Settings Catalog. Options:
  1. **Import Brave's ADMX** (Intune **Devices > Manage devices > Configuration > Import ADMX**, then a profile of type **Templates > Imported Administrative templates (Preview)**). Limits: at most 20 ADMX files, each 1 MB or smaller, only an `en-us` ADML, dependencies imported first, no combo-box settings ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/import-custom-admx-templates)). A 2023 community report says `brave.admx` fails with `NamespaceMissing:BraveSoftware.Policies` until a small parent `bravesoftware.admx`/`.adml` is uploaded first; check the current templates.
  2. **Registry**: write `ExtensionSettings` (REG_SZ, the Chrome JSON) under the Brave root with a script or Win32 app. [`policy/examples/brave-extensionsettings.reg`](../policy/examples/brave-extensionsettings.reg) shows the value.
- **macOS**: preference domain `com.brave.Browser` (Preference file template, or a custom profile modelled on the Chrome example with `com.google.Chrome` replaced by `com.brave.Browser`).

### 3.7 Alternatives: OMA-URI with ADMX ingestion

Before Chrome and Edge were built into the Settings Catalog, policies were set through custom OMA-URI profiles after ingesting the browser's ADMX. This still works and Microsoft documents it for Edge ([Configure Microsoft Edge using MDM](https://learn.microsoft.com/deployedge/configure-edge-with-mdm)):

1. Custom profile (**Windows 10 and later > Templates > Custom**), row 1 ingests the unmodified `msedge.admx`: OMA-URI `./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/Edge/Policy/EdgeAdmx`, type String, value = the whole ADMX file.
2. Further rows set policies. Path pattern: `./Device/Vendor/MSFT/Policy/Config/Edge~Policy~microsoft_edge~Extensions/<PolicyName>`, data type String. Examples:

   | Policy | Value |
   |---|---|
   | `ExtensionInstallForcelist` | `<enabled/><data id="ExtensionInstallForcelistDesc" value="1&#xF000;<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx"/>` (list items are separated by `&#xF000;`) |
   | `ExtensionSettings` | `<enabled/><data id="ExtensionSettings" value="{&quot;<EDGE_ADDONS_ID>&quot;:{...}}"/>`; the `id` is the `<text>` element id of the policy in `msedge.admx` (open the ADMX and check), and the JSON must be XML-escaped |

Do not set the same policy through both an OMA-URI profile and the Settings Catalog. Prefer the Settings Catalog.

The legacy **Templates > Administrative Templates** profile type is deprecated and read-only since Intune release 2412 ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-admx-templates-windows)).

### 3.8 Registry files for testing

[`policy/examples/*-extensionsettings.reg`](../policy/examples/) set `ExtensionSettings` for one machine. Replace the id placeholder first. They are meant for a lab device or a VM, not for production.

---

## 4. Step 2: configure Bastion Shield (managed storage)

### 4.1 How it works

Bastion Shield declares a managed-storage schema ([`policy/managed_schema.json`](../policy/managed_schema.json), shipped in the package). Chromium reads values for an extension from:

| Platform | Location |
|---|---|
| Windows, Edge | `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy` |
| Windows, Chrome | `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy` |
| Windows, Brave | `HKLM\SOFTWARE\Policies\BraveSoftware\Brave\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy` |
| macOS, Edge | preference domain `com.microsoft.Edge.extensions.<EDGE_ADDONS_ID>` |
| macOS, Chrome | preference domain `com.google.Chrome.extensions.<CHROME_WEB_STORE_ID>` |
| macOS, Brave | preference domain `com.brave.Browser.extensions.<CHROME_WEB_STORE_ID>` |

`HKCU` works too, but standard users cannot write below `Software\Policies`, so use `HKLM` from a SYSTEM context. Microsoft documents the same mechanism for one of its own extensions, using exactly the Edge path above ([Azure Virtual Desktop multimedia redirection](https://learn.microsoft.com/azure/virtual-desktop/multimedia-redirection-video-playback-calls)). The values are only read once the extension is installed. Values that do not match the schema are not passed to the extension ([Chrome storage.managed](https://developer.chrome.com/docs/extensions/reference/manifest/storage)). The browser sends `storage.onChanged` when policy changes and Bastion Shield re-applies everything at once.

Every key is optional. **A key that is present overrides the user's setting and locks that control** in the dashboard, which then shows a lock icon.

### 4.2 Keys

| Key | Type | Effect | Default when not set |
|---|---|---|---|
| `organizationName` | string | Shown as «Verwaltet von …» / "Managed by …" in popup and dashboard; suppresses the welcome page | none |
| `supportUrl` | string | Link to your IT support next to the organisation name | none |
| `supportEmail` | string | Recipient of "Report a broken site" when `reportBrokenSite` is `email`. Setting it without `reportBrokenSite` switches the button to `email` | none |
| `reportBrokenSite` | `github` / `email` / `none` | `github`: opens a prefilled public GitHub issue the user reviews and submits; `email`: opens a mail to `supportEmail`; `none`: hides the button | `email` when `supportEmail` is set, otherwise `github` |
| `defaultMode` | `standard` / `aggressive` | Blocking mode for all sites (see [PARITY.md](PARITY.md)) | `standard` |
| `aggressiveSites` | list of hostnames | Sites forced to aggressive mode, subdomains included; users cannot change the mode on them | none |
| `disabledSites` | list of hostnames | Sites where Bastion Shield does not filter at all (subdomains included). The setting follows the page in the address bar: a disabled site's pages and everything they load are unfiltered, while the same site embedded as an iframe in another site stays filtered. Use plain lower-case hostnames such as `intranet.example.com`: no scheme, path, port or `*` | none |
| `allowUserSiteToggle` | boolean | `false` locks the per-site on/off switch | `true` |
| `lists` | object, list id → boolean | Force lists on or off, e.g. `{"annoyances": true, "regional-it": false}`. Ids: [FILTER-LISTS.md](FILTER-LISTS.md) | catalog defaults |
| `lockLists` | boolean | `true`: users cannot change any list, and lists not named in `lists` use their catalog default. `lockSettings: true` implies it unless `lockLists` is explicitly `false` | `false` (`true` under `lockSettings`) |
| `customFilters` | list of strings | Admin filters in uBlock Origin syntax (network and cosmetic; scriptlet filters are ignored) | none |
| `allowUserFilters` | boolean | `false` makes the user filter editor read-only. `lockSettings: true` does the same unless `allowUserFilters` is explicitly `true` | `true` (`false` under `lockSettings`) |
| `allowCustomLists` | boolean | `false`: users cannot import filter lists (Filter lists › My lists), and lists they imported earlier are **not applied** and no longer downloaded. Use it for managed clients that must only run the lists you chose. `lockSettings: true` does the same unless `allowCustomLists` is explicitly `true` | `true` (`false` under `lockSettings`) |
| `lockSettings` | boolean | Locks every dashboard setting (privacy, badge, activity log, history, default mode), every filter list, the per-site mode, script and fingerprinting settings, the user filter editor and imported lists. `"lockLists": false` keeps the lists editable, `"allowUserFilters": true` the editor and `"allowCustomLists": true` the imported lists. The per-site protection switch follows `allowUserSiteToggle` | `false` |
| `gpc` | boolean | Global Privacy Control header and `navigator.globalPrivacyControl` | `true` |
| `stripParams` | boolean | Remove tracking parameters on cross-site navigation | `true` |
| `debounce` | boolean | Skip known bounce-tracking redirects | `true` |
| `deAmp` | boolean | Redirect AMP pages to the publisher's page | `true` |
| `fingerprinting` | `off` / `standard` / `strict` | Default fingerprinting protection | `standard` |
| `blockHyperlinkAuditing` | boolean | Disable `<a ping>` | `true` |
| `disablePrivacySandboxAds` | boolean | Turn off Topics, Protected Audience, Attribution Reporting | `true` |
| `webrtcPolicy` | `default` / `default_public_interface_only` / `disable_non_proxied_udp` | WebRTC IP handling through the extension API | `default` (browser's) |
| `blockThirdPartyCookies` | boolean | Third-party cookie setting through the extension API | browser's setting |
| `showBadge` | boolean | Blocked count on the toolbar icon | `true` |
| `showIncidentCta` | boolean | «Cyber-Vorfall?» button in the popup and navigation (link to the Bastion incident contact form). `false` shows the Bastion Shield name instead | `true` |
| `activityLog` | boolean | Live per-tab activity in popup and dashboard (memory only). `false`: no individual requests are kept, shown or written to the history. While `showBadge` and `gpc` are both on, blocked requests are still counted for the badge and the totals ([PRIVACY.md](PRIVACY.md#what-the-extension-observes)) | `true` |
| `historyEnabled` | boolean | Keep a blocking history on the device | `true` |
| `historyRetentionDays` | integer 0-3650 | Days of history to keep; 0 keeps only today's totals | `30` |
| `protectionEnabled` | boolean | Emergency switch: `false` switches protection off on every site of every device that receives the policy, without uninstalling ([section 9](#9-emergency-switch-protection-off-fleet-wide)) | `true` |

For `webrtcPolicy` and `blockThirdPartyCookies`, a browser policy (section 6) is the stronger tool: browser policies override settings that extensions make through `chrome.privacy`.

### 4.3 Registry encoding (Windows)

From Chromium's registry reader ([`registry_dict.cc`](https://github.com/chromium/chromium/blob/main/components/policy/core/common/registry_dict.cc)):

| Schema type | Registry |
|---|---|
| boolean | `REG_DWORD` 0 or 1 |
| integer | `REG_DWORD` |
| string | `REG_SZ` |
| list | a sub-key with `REG_SZ` values named `1`, `2`, `3` … **or** one `REG_SZ` holding a JSON array (`["a.example","b.example"]`) |
| object (`lists`) | a sub-key with one value per entry **or** one `REG_SZ` holding a JSON object (`{"annoyances":true}`) |

`REG_MULTI_SZ` is not supported. Value names are matched case-insensitively. Numbered list values are read in sorted order, so use a JSON string where order matters (`customFilters`). Examples: [`bastion-shield-policy-edge.reg`](../policy/examples/bastion-shield-policy-edge.reg), [`-chrome.reg`](../policy/examples/bastion-shield-policy-chrome.reg), [`-brave.reg`](../policy/examples/bastion-shield-policy-brave.reg).

### 4.4 Delivering the values on Windows

No browser exposes extension policy in the Intune Settings Catalog. Custom ADMX ingestion is not allowed to write below `Software\Policies\Microsoft` (with a short list of exceptions that does not include the Edge path) ([Microsoft Learn](https://learn.microsoft.com/windows/client-management/win32-and-centennial-app-policy-configuration)), and the Intune import applies the same restriction ("Not all areas of the registry can be set using custom ADMX", [Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/settings-catalog/import-custom-admx-templates)). Microsoft's own `msedge.admx` does write there, so the public exception list looks incomplete, but we have not tested a custom ADMX for the Edge `3rdparty` path. For Chrome and Brave a custom ADMX would be allowed; Bastion does not ship one yet.

The supported route for all three browsers is therefore the script [`Set-BastionShieldPolicy.ps1`](../policy/examples/Set-BastionShieldPolicy.ps1):

- validates the configuration against the schema before changing anything (unknown keys, wrong types, hostnames with scheme or wildcard);
- writes `HKLM` in the 64-bit registry view even when Intune runs it in a 32-bit host;
- is **idempotent**: removes values and sub-keys that are no longer configured, leaves matching values untouched;
- `-Mode Detect` exits 0 and prints one line when everything matches, 1 otherwise; `-Mode Remove` deletes its keys (rollback);
- logs to `%ProgramData%\BastionShield\Logs\BastionShieldPolicy.log`;
- skips browsers whose id is still a placeholder.

Its input is a small JSON document ([`bastion-shield-policy.example.json`](../policy/examples/bastion-shield-policy.example.json)):

```json
{
  "extensionIds": { "edge": "<EDGE_ADDONS_ID>", "chrome": "<CHROME_WEB_STORE_ID>", "brave": "<CHROME_WEB_STORE_ID>" },
  "policy": {
    "organizationName": "Muster AG",
    "supportEmail": "it-support@example.com",
    "reportBrokenSite": "email",
    "disabledSites": ["intranet.example.com"],
    "lockSettings": true
  }
}
```

With `"lockSettings": true` users cannot change filter lists, per-site settings, their own filters or imported lists either (imported lists are then switched off). Add `"lockLists": false`, `"allowUserFilters": true` or `"allowCustomLists": true` to leave those editable.

The script reads, in this order: `-ConfigPath`, `bastion-shield-policy.json` next to the script, or the `$EmbeddedConfig` block inside the script. Test it on one machine first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BastionShieldPolicy.ps1 -ConfigPath .\bastion-shield-policy.json -WhatIf
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BastionShieldPolicy.ps1 -ConfigPath .\bastion-shield-policy.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BastionShieldPolicy.ps1 -ConfigPath .\bastion-shield-policy.json -Mode Detect
```

Choose one Intune delivery method:

| Method | Re-applies after drift | Licence / device requirements | Steps |
|---|---|---|---|
| **Remediation** (recommended where licensed) | yes, on its schedule (default daily) | Windows Enterprise E3/E5, Education A3/A5 or VDA per user; devices Entra-joined or hybrid-joined, MDM-enrolled or co-managed ([Microsoft Learn](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)) | Paste your JSON into `$EmbeddedConfig` of **both** `Detect-BastionShieldPolicy.ps1` (detection script) and `Set-BastionShieldPolicy.ps1` (remediation script). **Devices > Scripts and remediations > Remediations > Create**. Run as system (logged-on credentials: **No**), **64-bit PowerShell: Yes**, signature check as per your policy. Schedule daily. |
| **Win32 app** (recommended otherwise) | yes, when detection fails (Intune re-evaluates apps periodically) | Intune Management Extension (any Intune-managed Windows) | Package `Set-BastionShieldPolicy.ps1` and `bastion-shield-policy.json` with the Win32 Content Prep Tool. Install command `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BastionShieldPolicy.ps1`, uninstall command `... -Mode Remove`, install behaviour **System**. Detection: **custom script** = `Detect-BastionShieldPolicy.ps1` with the same JSON in `$EmbeddedConfig` (it exits 0 and writes to stdout only when compliant). For a configuration change, publish a new app version. |
| **Platform script** | no: runs once, again only when the script changes | devices **joined** to Entra ID (registered-only devices do not receive scripts) ([Microsoft Learn](https://learn.microsoft.com/intune/device-management/tools/run-powershell-scripts-windows)) | Paste your JSON into `$EmbeddedConfig`. **Devices > Scripts and remediations > Platform scripts > Add > Windows 10 and later**. Logged-on credentials **No**, **64-bit PowerShell host: Yes**. The script must stay under 200 KB. |

Both script files must stay ASCII-only (Windows PowerShell 5.1 reads files without a byte-order mark as ANSI). CI checks that `Detect-BastionShieldPolicy.ps1` is identical to `Set-BastionShieldPolicy.ps1` apart from its default mode.

### 4.5 Delivering the values on macOS

Use the second payload of [`com.microsoft.Edge.mobileconfig`](../policy/examples/com.microsoft.Edge.mobileconfig) or [`com.google.Chrome.mobileconfig`](../policy/examples/com.google.Chrome.mobileconfig): its `PayloadType` is the extension's preference domain (`com.microsoft.Edge.extensions.<id>`, `com.google.Chrome.extensions.<id>`), and its keys are the policy keys with native plist types (`<true/>`, `<integer>`, `<array>`, `<dict>`). Chromium reads values that a profile forces as mandatory policy ([`policy_loader_mac.mm`](https://github.com/chromium/chromium/blob/main/components/policy/core/common/policy_loader_mac.mm)). Alternatively create a **Preference file** profile with the preference domain `com.google.Chrome.extensions.<id>` (one profile per domain).

Replace the id placeholders (`EDGE_ADDONS_ID` / `CHROME_WEB_STORE_ID` inside the XML) and generate new `PayloadUUID`s (`uuidgen`) before uploading.

---

## 5. Step 3: verify

Allow time: Intune devices check in roughly every 8 hours (and on change notifications); Chromium re-reads platform policy every 15 minutes ([Microsoft Learn](https://learn.microsoft.com/intune/device-configuration/troubleshoot-device-profiles)). To speed up a test, sync the device from Company Portal or *Settings > Accounts > Access work or school > Info > Sync*, then click **Reload policies** on the policy page.

On a test device:

1. **Policy page**: `edge://policy`, `chrome://policy` or `brave://policy`.
   - `ExtensionSettings` (or `ExtensionInstallForcelist`) is listed with status **OK**. Open it to check the JSON.
   - An entry prefixed with `[BLOCKED]` or a warning means the browser refused it: usually an off-store `update_url` on a device it does not consider managed (section 7), or a typo in a store URL.
   - Chrome and Brave list extension policy in a separate section for the extension id. Edge may not list `3rdparty` extension values on `edge://policy`; then use the registry check and the dashboard below.
2. **Extensions page**: `edge://extensions`, `chrome://extensions`, `brave://extensions`. Bastion Shield is present and marked as installed or managed by your organisation (the wording varies by browser and version); the remove button and the toggle are disabled.
3. **Bastion Shield dashboard** (open it from the popup, or right-click the toolbar icon > Options): the header shows «Verwaltet von Muster AG» (English UI: "Managed by Muster AG"), and locked settings carry a lock icon. Sites in `disabledSites` show protection as off and locked in the popup. With `protectionEnabled: false` the popup shows that protection is switched off on all sites.
4. **Registry** (Windows), for example:

   ```powershell
   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy'
   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name ExtensionSettings
   ```

5. **Intune**: the device configuration report of each profile, and the script/remediation or app status per device.

Developer tools are disabled for policy-installed extensions by default (`DeveloperToolsAvailability` = 0 in [Edge](https://learn.microsoft.com/deployedge/microsoft-edge-policies/developertoolsavailability) and [Chrome](https://chromeenterprise.google/policies/#DeveloperToolsAvailability)), so use the dashboard rather than the extension's console to check what it received.

---

## 6. Complementary browser policies

Some protections are better done by the browser itself, and some cannot be done by an extension at all (see [PARITY.md](PARITY.md)). These policies complement Bastion Shield. Test them with a pilot group: several can affect business applications.

| Goal | Edge policy | Chrome / Brave policy | Suggested value | Notes |
|---|---|---|---|---|
| Block third-party cookies | [`BlockThirdPartyCookies`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/blockthirdpartycookies) | [`BlockThirdPartyCookies`](https://chromeenterprise.google/policies/#BlockThirdPartyCookies) | Enabled | Check single sign-on and embedded apps that rely on third-party cookies; exceptions via `CookiesAllowedForUrls`. |
| Upgrade to HTTPS | [`HttpsUpgradesEnabled`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/httpsupgradesenabled) (Edge 136+, replaces `AutomaticHttpsDefault`) | [`HttpsUpgradesEnabled`](https://chromeenterprise.google/policies/#HttpsUpgradesEnabled) | Enabled | Extensions cannot upgrade with fallback the way the browser does, so this replaces Brave's HTTPS upgrade. Exceptions: `HttpAllowlist`. |
| Warn before plain HTTP | [`HttpsOnlyMode`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/httpsonlymode) (Edge 140+) | [`HttpsOnlyMode`](https://chromeenterprise.google/policies/#HttpsOnlyMode) (`force_balanced_enabled` from Chrome 129) | `force_balanced_enabled` | `force_enabled` is the strict variant. |
| Encrypted DNS | [`DnsOverHttpsMode`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/dnsoverhttpsmode) + `DnsOverHttpsTemplates` | [`DnsOverHttpsMode`](https://chromeenterprise.google/policies/#DnsOverHttpsMode) + `DnsOverHttpsTemplates` | per customer | On managed devices, an unset policy means **no** DNS-over-HTTPS. Align with the customer's DNS filtering; `secure` bypasses an on-premises DNS filter. |
| Hide local IP from WebRTC | [`WebRtcLocalhostIpHandling`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/webrtclocalhostiphandling) (needs a browser restart) | [`WebRtcIPHandling`](https://chromeenterprise.google/policies/#WebRtcIPHandling) | `default_public_interface_only` | Test Teams and video conferencing first; Microsoft documents that this can break eCDN peer connections. |
| Edge's own tracker blocking | [`TrackingPrevention`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/trackingprevention) | n/a | `2` (Balanced) | Runs independently of Bastion Shield. A site in Bastion's `disabledSites` is still subject to it; mirror such sites into [`AllowTrackingForUrls`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/allowtrackingforurls) if they break. |
| Protection in private windows | [`MandatoryExtensionsForInPrivateNavigation`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/mandatoryextensionsforinprivatenavigation) (Edge 139+) | n/a (Chrome's equivalent is ChromeOS-only); [`IncognitoModeAvailability`](https://chromeenterprise.google/policies/#IncognitoModeAvailability) = 1 disables Incognito | Edge: `["<EDGE_ADDONS_ID>"]` | InPrivate stays blocked until the user allows the listed extensions in InPrivate (and is blocked if the extension is missing). |
| No developer mode | [`ExtensionDeveloperModeSettings`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/extensiondevelopermodesettings) (128+) | [`ExtensionDeveloperModeSettings`](https://chromeenterprise.google/policies/#ExtensionDeveloperModeSettings) (128+) | `1` (disallow) | Stops users from loading unpacked extensions. |
| No DevTools on managed extensions | [`DeveloperToolsAvailability`](https://learn.microsoft.com/deployedge/microsoft-edge-policies/developertoolsavailability) | [`DeveloperToolsAvailability`](https://chromeenterprise.google/policies/#DeveloperToolsAvailability) | leave default `0` | `0` already blocks DevTools for policy-installed extensions. |
| Chrome's intrusive-ads filter | n/a | [`AdsSettingForIntrusiveAdsSites`](https://chromeenterprise.google/policies/#AdsSettingForIntrusiveAdsSites) | `2` | Chrome only. |

**Brave** ([Brave Help Center](https://support.brave.app/hc/en-us/articles/360039248271-Group-Policy)): `BraveShieldsDisabledForUrls` / `BraveShieldsEnabledForUrls` (URL lists, no wildcards; mirror Bastion's `disabledSites` here so both blockers stand down on the same sites), `BraveP3AEnabled` = false, `BraveStatsPingEnabled` = false, `BraveWebDiscoveryEnabled` = false, `BraveRewardsDisabled` = true, `BraveWalletDisabled` = true, `BraveAIChatEnabled` = false, `TorDisabled` = true, as your privacy policy requires.

When both a browser policy and Bastion Shield's own setting (`webrtcPolicy`, `blockThirdPartyCookies`) are configured, the browser policy wins; the extension then shows the setting as controlled by the browser.

---

## 7. Self-hosting the extension (advanced)

Only consider this for fully managed fleets, staged rollouts or urgent fixes outside store review.

**When browsers accept an extension from outside their store:**

| Browser | Windows | macOS |
|---|---|---|
| Chrome (policy text) | joined to Active Directory, **or** joined to Microsoft Entra ID, **or** enrolled in Chrome Enterprise Core ([ExtensionSettings](https://chromeenterprise.google/policies/#ExtensionSettings)) | MDM-managed, MCX or Chrome Enterprise Core |
| Chrome (source code) | Chromium also treats MDM-registered devices (not Windows Home) as trusted for policy loading, but not Entra-*registered* (workplace-joined) devices, and the managed state can be unknown right after a fresh install. Untested; do not rely on it. | |
| Edge | Microsoft's pages disagree: the [ExtensionSettings page](https://learn.microsoft.com/deployedge/microsoft-edge-policies/extensionsettings) requires an Active Directory domain or Microsoft Entra join, the [ExtensionInstallForcelist page](https://learn.microsoft.com/deployedge/microsoft-edge-policies/extensioninstallforcelist) mentions only Active Directory, and the [self-hosting page](https://learn.microsoft.com/deployedge/microsoft-edge-manage-extensions-webstore) says Entra-joined devices need hybrid join. **Test on your device types before planning on it.** | MDM or MCX |

Chrome Enterprise Core is free; Intune can enrol Chrome by writing `HKLM\SOFTWARE\Policies\Google\Chrome\CloudManagementEnrollmentToken` ([Google](https://support.google.com/chrome/a/answer/10728773)). On a device the browser does not trust, the off-store entry is marked `[BLOCKED]` on the policy page.

**What Bastion provides** (see [RELEASING.md](RELEASING.md)): a signed CRX and `update.xml` per release when self-hosting is enabled. The self-hosted extension has **its own id** (derived from Bastion's signing key), different from both store ids, so the managed-configuration paths use that id too.

**Hosting requirements:**

- HTTPS, reachable from wherever users are, without authentication ([Microsoft Learn](https://learn.microsoft.com/deployedge/microsoft-edge-manage-extensions-webstore)).
- Serve the CRX as `Content-Type: application/x-chrome-extension` ([Microsoft Learn](https://learn.microsoft.com/troubleshoot/microsoft-edge/development/self-host-extension-deploy)) and do not send `X-Content-Type-Options: nosniff` for it ([Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux)).
- `update.xml` in gupdate format:

  ```xml
  <?xml version='1.0' encoding='UTF-8'?>
  <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
    <app appid='<SELF_HOSTED_ID>'>
      <updatecheck codebase='https://updates.example.com/bastion-shield/bastion-shield-1.0.0.2910.crx' version='1.0.0.2910' />
    </app>
  </gupdate>
  ```

**Policy** (Edge shown; for Chrome and Brave use `toolbar_pin`):

```json
{"<SELF_HOSTED_ID>":{"installation_mode":"force_installed","update_url":"https://updates.example.com/bastion-shield/update.xml","override_update_url":true,"toolbar_state":"force_shown"}}
```

Microsoft recommends `override_update_url: true` for self-hosted extensions; without it Edge may ignore the custom update URL ([Microsoft Learn](https://learn.microsoft.com/troubleshoot/microsoft-edge/development/self-host-extension-update)).

---

## 8. Rollout, updates and rollback

**Rollout.** Assign profiles to a pilot device group (IT and a few volunteers from each department) for one to two weeks, then to all devices. Use Intune assignment filters to separate Windows and macOS. Watch the broken-site reports from the pilot before widening.

**Updates.** Nothing to do: Bastion publishes a release every week with fresh filter lists (and on demand for fixes). Browsers check for extension updates shortly after start and then about every 5 hours. Chrome Web Store updates that only change safe network rules can go live within minutes; others take from hours to days. Edge Add-ons certification takes up to 7 business days, so Edge devices lag behind Chrome by up to a week. See [RELEASING.md](RELEASING.md).

**Rollback and emergency measures:**

| Situation | Action |
|---|---|
| One site breaks for everyone | Add its hostname to `disabledSites` (takes effect at the next policy refresh) and report it so the filter can be fixed. Users can also switch protection off for a site themselves unless `allowUserSiteToggle` is `false`. |
| One filter list causes problems | Force it off: `"lists": {"<list-id>": false}`. |
| A Bastion Shield release misbehaves | Bastion publishes a corrected higher version (stores cannot roll back to an older version). In the meantime: `disabledSites` for the affected sites, or `"protectionEnabled": false` to switch protection off everywhere without uninstalling ([section 9](#9-emergency-switch-protection-off-fleet-wide)). |
| Remove the configuration | Run `Set-BastionShieldPolicy.ps1 -Mode Remove` (or the Win32 app's uninstall), or delete the macOS profile. The extension keeps running with its defaults. |
| Remove the extension | Remove its entry from `ExtensionSettings` (or set `"installation_mode": "removed"`), or unassign the profile. The browser uninstalls it; its local settings and history are deleted with it. |

---

## 9. Emergency: switch protection off fleet-wide

Use this when Bastion Shield breaks business applications on many sites at once (for example after a faulty release or filter update) and `disabledSites` or forcing a list off is not enough. The extension stays installed, so nothing has to be reinstalled afterwards, and user settings, site exceptions and history are kept.

**What `"protectionEnabled": false` does** on every device that receives it:

- Requests are no longer blocked or redirected on any site: an `allowAllRequests` rule overrides every filter list, the strict-block page and debouncing. Admin and user filters are suspended, and the Global Privacy Control header is no longer sent.
- No cosmetic filters, scriptlets or privacy scripts are injected into new pages.
- The extension releases the browser settings it controls (through `chrome.privacy`: hyperlink auditing, Privacy Sandbox ad APIs, WebRTC, third-party cookies; and per-site script blocking). Browser policies you set yourself (section 6) are not affected.
- The popup shows that protection is switched off on all sites, and users cannot switch it back on.

**How to switch it on (Windows):**

1. Add `"protectionEnabled": false` to the `policy` block of your configuration: `$EmbeddedConfig` in **both** `Set-BastionShieldPolicy.ps1` and `Detect-BastionShieldPolicy.ps1` (Remediation, platform script), or `bastion-shield-policy.json` (Win32 app). The shipped examples already contain `"protectionEnabled": true`; change it to `false`.
2. Deploy the change the way you deployed the configuration. A Remediation is fastest: update both scripts, then use **Run remediation** on the affected devices or wait for the schedule. Win32 app: publish a new app version. Platform script: upload the changed script (it runs again because its content changed).
3. On test devices, speed things up with an Intune sync and **Reload policies** on `edge://policy` or `chrome://policy`.

Do **not** only write the registry value by hand on devices that also run the Remediation or the Win32 app: the script is idempotent and removes or resets values that differ from its configuration, so its next run would switch protection back on. For a single lab device without the script:

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy" /v protectionEnabled /t REG_DWORD /d 0 /f
```

**macOS:** set `<key>protectionEnabled</key><false/>` in the extension payload of the configuration profile (section 4.5) and upload the new version.

**Timing.** The device must receive the policy (Intune check-in roughly every 8 hours, or a manual sync); the browser then re-reads policy within 15 minutes. Bastion Shield applies the change as soon as the browser hands it over, also when its service worker was idle. Network rules change for the next request. Pages that are already open keep the cosmetic hiding and scripts they already received until they are reloaded.

**Switching protection back on.** Set `"protectionEnabled": true` or remove the key, and deploy the same way. Lists, site exceptions and settings come back as they were. Ask users to reload open tabs.

**Scope.** The switch applies to every device the configuration is assigned to. To switch protection off for one department only, assign a separate configuration to that group. For a single site, use `disabledSites` instead.

---

## FAQ

### Why are there two different extension ids?
The Chrome Web Store and Edge Add-ons each assign their own id when an extension is published. Chrome and Brave use the Chrome Web Store id; Edge uses the Edge Add-ons id. (Edge can install from the Chrome Web Store too, but then updates and certification follow Google's store; we publish to Edge Add-ons for Edge.)

### Can users switch Bastion Shield off?
They cannot remove or disable a force-installed extension. They can switch protection off for a single site in the popup, unless `allowUserSiteToggle` is `false`, and they can change settings unless they are locked by policy.

### Does it work in Incognito / InPrivate windows?
Force-install policies do not apply to Incognito or InPrivate ([Chrome](https://chromeenterprise.google/policies/#ExtensionInstallForcelist), [Edge](https://learn.microsoft.com/deployedge/microsoft-edge-policies/extensioninstallforcelist)); users have to allow the extension there. On Edge 139+, `MandatoryExtensionsForInPrivateNavigation` makes InPrivate unusable until they do. On Chrome, the only enforcement is disabling Incognito (`IncognitoModeAvailability`).

### Does Bastion Shield send data to Bastion or anyone else?
No. There is no telemetry, no remote configuration and no account. Blocking history stays on the device. The browser itself contacts the store to check for updates, as for every extension. Details: [PRIVACY.md](PRIVACY.md).

### Should we deploy Bastion Shield to Brave?
Brave Shields blocks requests before any extension sees them. Running both is safe and does not double-block network requests, but on Brave: the blocked counts in Bastion Shield are lower (0 on the four news sites we checked, see [PARITY.md](PARITY.md#edge-and-brave)); switching Bastion Shield off for a site does not unblock what Shields blocks (lower Shields too, or use `BraveShieldsDisabledForUrls`); cosmetic filters run twice. Recommended: keep Brave Shields on and deploy Bastion Shield to Brave only if you want its central configuration, Bastion's own filter list or the activity view.

### We already use Edge Tracking Prevention. Do we still need Bastion Shield?
They complement each other. Tracking Prevention, based on Disconnect's lists, mainly restricts storage access for known trackers in Balanced mode (Strict also blocks more of their loads) and is not an ad blocker; Bastion Shield blocks ads, trackers, malware domains and cookie banners at network and page level. Keep both; add problem sites to both exception lists.

### How long until a change reaches the devices?
Intune check-in (about every 8 hours, or a manual sync) plus up to 15 minutes until the browser re-reads policy. Extension updates follow the browser's update check (about every 5 hours) after the store has published them.

### What about devices that are not enrolled (BYOD)?
Without enrolment, Intune cannot set browser policies, so it cannot force-install. Users can install Bastion Shield themselves from the store.

### Will it break Microsoft 365 sign-in or Teams?
Bastion's own filter list contains exceptions that keep the Microsoft Entra sign-in pages working, and the default lists are the same ones uBlock Origin and Brave use. If a line-of-business application breaks, add it to `disabledSites` and report it (the popup's "Report a broken site", or your IT support with `reportBrokenSite` set to `email`).

### Is the extension policy visible on edge://policy?
Not always for `3rdparty` extension values. Check the registry and the Bastion Shield dashboard instead (section 5).
