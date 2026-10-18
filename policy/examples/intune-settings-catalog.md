# Intune Settings Catalog entries for Bastion Shield

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

A click-through checklist. Background, alternatives and caveats: [docs/DEPLOYMENT-INTUNE.md](../../docs/DEPLOYMENT-INTUNE.md).

Replace `<EDGE_ADDONS_ID>` and `<CHROME_WEB_STORE_ID>` with the store ids of Bastion Shield. All profiles: **Devices > Manage devices > Configuration > Create > New policy**, assign to a pilot **device** group first.

## Profile 1: Edge, Windows: install

- Platform **Windows 10 and later**, profile type **Settings catalog**
- Name: `Bastion Shield - Edge - install`

| Category | Setting | Value |
|---|---|---|
| Microsoft Edge > Extensions | Configure extension management settings | Enabled, `{"<EDGE_ADDONS_ID>":{"installation_mode":"force_installed","update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx","toolbar_state":"force_shown"}}` |

Pick the device setting, not the one marked `(User)`. If the tenant already sets this policy (for example `"*": {"installation_mode": "blocked"}`), merge the Bastion Shield entry into the existing JSON in the existing profile.

## Profile 2: Chrome, Windows: install

- Platform **Windows 10 and later**, profile type **Settings catalog**
- Name: `Bastion Shield - Chrome - install`

| Category | Setting | Value |
|---|---|---|
| Google > Google Chrome > Extensions | Extension management settings | Enabled, `{"<CHROME_WEB_STORE_ID>":{"installation_mode":"force_installed","update_url":"https://clients2.google.com/service/update2/crx","toolbar_pin":"force_pinned"}}` |

Alternative (no toolbar pinning): *Configure the list of force-installed apps and extensions* = `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx`. Use one of the two.

## Profile 3: Edge, macOS: install

- Platform **macOS**, profile type **Settings catalog**
- Name: `Bastion Shield - Edge macOS - install`

| Category | Setting | Value |
|---|---|---|
| Microsoft Edge > Extensions | Configure extension management settings | same JSON as profile 1 |

Or upload `com.microsoft.Edge.mobileconfig` as **Templates > Custom** (device channel), which also carries the extension configuration. Do not do both for `ExtensionSettings`.

## Profile 4: Chrome, macOS: install and configure

Not in the Settings Catalog. Upload `com.google.Chrome.mobileconfig` as **macOS > Templates > Custom**, deployment channel **Device channel**.

## Profile 5: Brave, Windows

Not in the Settings Catalog. Import Brave's ADMX (**Configuration > Import ADMX**; import the parent `bravesoftware.admx` first if Intune reports `NamespaceMissing`), then **Templates > Imported Administrative templates (Preview)** and set *ExtensionSettings* to the Chrome JSON from profile 2. Or write the value with a script (`brave-extensionsettings.reg` shows it).

## Extension configuration (Windows, all browsers)

Not available in the Settings Catalog. Use `Set-BastionShieldPolicy.ps1` as a Remediation, Win32 app or platform script (run as system, 64-bit host). See section 4.4 of the deployment guide.

## Optional: privacy baseline

Separate profile(s), so they can be rolled back independently of the extension. Test with the pilot group; values are suggestions.

**Edge (Windows and macOS), category Microsoft Edge unless noted:**

| Setting (policy) | Value |
|---|---|
| Block third party cookies (`BlockThirdPartyCookies`) | Enabled |
| Enable automatic HTTPS upgrades (`HttpsUpgradesEnabled`) | Enabled |
| Allow HTTPS-Only Mode to be enabled (`HttpsOnlyMode`, Edge 140+) | Force enable HTTPS-Only Mode in Balanced Mode |
| Block tracking of users' web-browsing activity (`TrackingPrevention`) | Balanced |
| Extensions > Specify extensions users must allow in order to navigate using InPrivate mode (`MandatoryExtensionsForInPrivateNavigation`, Edge 139+) | `<EDGE_ADDONS_ID>` |
| Extensions > Control the availability of developer mode on extensions page (`ExtensionDeveloperModeSettings`) | Do not allow the usage of developer mode on extensions page |
| WebRtc settings > Restrict exposure of local IP address by WebRTC (`WebRtcLocalhostIpHandling`) | Allow public interface over http default route (test Teams first) |
| Control the mode of DNS-over-HTTPS (`DnsOverHttpsMode`) | per customer (coordinate with DNS filtering) |

**Chrome (Windows), category Google > Google Chrome:** `BlockThirdPartyCookies` = Enabled, `HttpsUpgradesEnabled` = Enabled, `HttpsOnlyMode` = Enable HTTPS-Only Mode in Balanced Mode, `ExtensionDeveloperModeSettings` = Do not allow, `AdsSettingForIntrusiveAdsSites` = Do not allow ads on sites with intrusive ads, `WebRtcIPHandling` = public interface only (after testing). Use the policy name in the settings picker search; display names vary slightly between catalog versions.
