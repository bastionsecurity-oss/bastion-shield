# Security policy

Bastion Shield runs with broad access to the pages its users visit. We take reports about its security seriously and are grateful for them.

## Reporting a vulnerability

Please **do not open a public issue**.

- Preferred: GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/bastionsecurity-oss/bastion-shield/security/advisories/new) (repository **Security** tab).
- Or e-mail [info@bastionsecurity.ch](mailto:info@bastionsecurity.ch) with "Security" in the subject. Please send only a short description and ask for a secure channel before sending exploit details.

Please include the affected version (popup or dashboard "About"), browser and version, steps to reproduce or a proof of concept, and the impact you see. English or German is fine.

What to expect (targets, in Zurich business days):

- acknowledgement within **3 days**;
- first assessment and severity within **10 days**;
- a fix released through the stores as fast as review allows, usually within **30 days** for high-severity issues;
- coordinated disclosure: we publish a GitHub security advisory once a fix is available, and credit you if you wish. Please give us **90 days** before disclosing publicly, or less once the fix is out.

We do not take legal action against good-faith research that respects users' privacy, avoids harm to others' data and services, and gives us reasonable time to fix the issue.

## Supported versions

Bastion Shield updates itself through the Chrome Web Store and Microsoft Edge Add-ons. Only the **latest published version** receives fixes. Because Edge Add-ons certification can take up to 7 business days, the previous version is also considered supported until the fix has reached both stores.

Self-hosted builds (CRX signed by Bastion) follow the same versions.

## Scope

In scope:

- the extension (service worker, content scripts, page-world scripts, popup, dashboard, extension pages);
- the filter compiler and build tools in this repository, and the release pipeline (`.github/`);
- the policy kit in `policy/` (schema, PowerShell scripts, profiles);
- the Bastion filter list (`filters/bastion.txt`), for example a filter that breaks a security feature of a site.

Examples of what we want to hear about: a website being able to read Bastion Shield's history or settings, run code in the extension's context, detect or disable protection beyond normal web-compat behaviour, abuse the warning or bounce page for redirects; a managed policy being bypassed by a user; anything that makes Bastion Shield send data off the device.

Out of scope: ads or trackers that are not blocked (use the issue forms), problems in third-party filter lists (report them upstream, see [CONTRIBUTING.md](CONTRIBUTING.md)), vulnerabilities in the browsers themselves (report them to Google, Microsoft or Brave), and the inherent limits of MV3 extensions described in [docs/PARITY.md](docs/PARITY.md) and [docs/PRIVACY.md](docs/PRIVACY.md#what-websites-can-see) (for example, that a page can detect the extension through a replaced script's `chrome-extension://` address).

## How we keep it secure

- No remote code: everything that runs is in the reviewed package; no telemetry and no network requests by the extension ([docs/PRIVACY.md](docs/PRIVACY.md)).
- Extension storage is restricted to trusted extension contexts; messages are validated by sender: content scripts may only send the cosmetic messages, and "proceed anyway" on the warning page is accepted only from that page's top frame and only for the host it actually blocked in that tab.
- Filters that can run code on pages (`trusted-*` scriptlets, trusted redirect resources) are accepted only from sources maintained by uBlock Origin, Brave or Bastion; trust is granted per source, and list text cannot switch it on.
- The fingerprinting seed is chosen from 2^64 combinations per browser session, and the per-site key is derived with HMAC-SHA-256, so a page cannot recover a cross-site identifier from the noise ([docs/ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-privacy-features)).
- Vendored third-party code is pinned to reviewed commits (`vendor/VENDOR.json`).
- Each release lists SHA-256 checksums of its assets and the exact inputs of the build; the self-hosting signing key is kept outside the repository with restricted access ([docs/RELEASING.md](docs/RELEASING.md)).
