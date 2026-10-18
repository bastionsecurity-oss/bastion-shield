# Releasing

How Bastion Shield is built, versioned, released and published to the Chrome Web Store and Microsoft Edge Add-ons, and how the optional self-hosting signing key is handled. Audience: Bastion maintainers.

## Version scheme

`MAJOR.MINOR.PATCH.BUILD`, for example `1.2.0.2913`.

- `MAJOR.MINOR.PATCH` come from `package.json` and change by hand: MAJOR for breaking changes to the managed policy or removed features, MINOR for features, PATCH for fixes.
- `BUILD` = days since 2026-01-01 × 10 + a same-day counter (0-9). 18 October 2026 is day 290, so the first build that day is `2900`, the second `2901`. Every release therefore has a higher version than the one before, even when only the filter lists changed, which both stores and the browser updater require. Each component must stay ≤ 65535 (Chromium's limit), which holds until 2043.
- The release workflow computes the counter from today's tags and passes it to the build as `BASTION_BUILD_COUNTER`; `tools/` writes the final version into `dist/manifest.json`.
- Git tags are `v<version>`, created by the release workflow on the commit it built.

## Continuous integration (`.github/workflows/ci.yml`)

On every push to `main`, every pull request and on demand, with Node 24 on Ubuntu:

1. `npm ci`
2. `npm run typecheck`, and `tsc -p .github/scripts` for the CI scripts
3. `npm test` (unit tests, `node:test`)
4. `node .github/scripts/check-policy.ts`: the managed schema against Chromium's rules and `ManagedPolicy`, and all policy examples; PowerShell parse check
5. Build in two passes, with the filter-list cache (`.cache/lists`, revalidated with ETag):
   1. `npm run build` fetches the lists and builds `dist/`;
   2. `npm run validate` (`tools/validate-dist.ts`) loads a copy of `dist/` in Playwright's Chromium with every ruleset enabled. It records the regexes that Chromium's RE2 rejects (`memoryLimitExceeded`) in `.cache/regex-unsupported.json` and exits non-zero on real problems: rulesets that do not enable, invalid selectors, rejected registrations;
   3. `node tools/build.ts --offline` rebuilds from the same cached lists and drops the recorded regexes.

   The RE2 program-size limit can only be checked in a browser, so a single pass would ship regexes that Chromium silently ignores, and e2e test 01-load (b) would fail. `.cache/regex-unsupported.json` is cached together with `.cache/lists`; validate merges new entries and never forgets old ones. Playwright's Chromium is installed before the build for this pass.
6. `node .github/scripts/check-budget.ts`: the default lists must fit 30,000 static rules and 1,000 regex rules; then `npm run package` (store zips in `dist-pkg/`)
7. `npm run test:e2e` in Playwright's Chromium under `xvfb-run`. Loading the **unpacked** build is the strict validator: Chromium refuses an unpacked extension with an invalid static rule, while a packed one would silently skip it
8. Artifacts: `dist/` and the store zips (14 days), `build-report.json` + `lock.json` (30 days), Playwright report on failure

`.github/workflows/policy.yml` runs the PowerShell remediation script against a test registry key on Windows (PowerShell 7 and 5.1) whenever `policy/` changes.

## Weekly release (`.github/workflows/release.yml`)

Runs every **Monday 03:00 UTC** and on demand (**Actions > Release > Run workflow**, options *force* and *publish*).

1. Find the previous release and download its `lock.json` and Chromium package.
2. Compute the build counter; type-check; unit tests; policy checks.
3. Build in two passes, exactly as in CI: `npm run build:release` (fresh download of all filter lists, full build), `npm run validate` (records the regexes Chromium rejects), then `node tools/build.ts --release --offline` (same list inputs, rejected regexes dropped). `BASTION_BUILD_COUNTER` is already set, so both passes produce the same version, and `--offline` rewrites `filters/lock.json` from the same cache entries.
4. Budget check; read the version from `dist/manifest.json` and refuse to continue if the tag exists.
5. **Decide**: release only if a filter source changed (compared by SHA-256 against the previous `lock.json`), code changed since the previous tag (`src`, `tools`, `vendor`, `filters/catalog.json`, `filters/bastion.txt`, `package*.json`), or *force* was set. Otherwise the run ends green without a release.
6. e2e tests, `npm run package` (writes `dist-pkg/`).
7. **Skip-review check** (`.github/scripts/skip-review-check.ts`): compares the new package with the previous one (see below).
8. Assemble the assets:
   - `bastion-shield-<version>-chromium.zip` (Chrome Web Store, also Brave)
   - `bastion-shield-<version>-edge.zip` (Edge Add-ons variant: same content, rulesets moved to the package root)
   - `lock.json`, `build-report.json`
   - `bastion-shield-<version>-filter-sources.tar.gz`: the raw lists exactly as the build consumed them, with `filters/catalog.json`, `filters/bastion.txt` and `filters/lock.json`
   - `SHA256SUMS.txt`
9. Create the tag and GitHub release with generated notes (per-list rule counts, vendored commits, corresponding-source note).
10. Submit to the stores (jobs `publish-cws`, `publish-edge`), each in its own GitHub environment and only if its credentials are configured.
11. Optionally sign a self-hosted CRX (job `self-host`, see below).

The GitHub release (tag, notes, `lock.json`, raw snapshots) is the GPL corresponding source for the compiled rulesets; see [FILTER-LISTS.md §5](FILTER-LISTS.md#corresponding-source-gpl). Never delete releases that were published to a store.

**Keeping the schedule alive.** GitHub disables scheduled workflows in public repositories after 60 days without repository activity. Releases do not commit anything, so keep merging Dependabot pull requests (weekly) and watch for the "scheduled workflow disabled" e-mail. Add an external check that alerts when the latest release is older than 14 days.

## Store publishing

Both stores need the **first** submission done by hand: create the listing, privacy disclosures (Bastion Shield collects no user data; justify each permission with the texts from [PRIVACY.md](PRIVACY.md)), screenshots and visibility (Public; Unlisted/Hidden if a customer requires it). After that the workflow updates the existing item.

### Chrome Web Store (API v2)

Setup ([Use the Chrome Web Store API](https://developer.chrome.com/docs/webstore/using-api)):

1. Google account with 2-step verification, as the publisher of the item.
2. Google Cloud project with the **Chrome Web Store API** enabled, OAuth consent screen, OAuth client (web application). Obtain a refresh token for the scope `https://www.googleapis.com/auth/chromewebstore`. A [service account](https://developer.chrome.com/docs/webstore/service-accounts) is the alternative for unattended use.
3. Publisher id: Developer Dashboard > Publisher > Settings. Item id: the extension id.
4. GitHub environment `chrome-web-store` (add required reviewers if a human should approve each submission) with the secrets below.

What the job does (`.github/scripts/store-publish.ts cws`): exchange the refresh token for an access token; `POST https://chromewebstore.googleapis.com/upload/v2/publishers/{publisherId}/items/{itemId}:upload` with the ZIP; poll `…:fetchStatus` while the upload is `IN_PROGRESS`; then `POST …/v2/publishers/{publisherId}/items/{itemId}:publish` with `{"publishType": "DEFAULT_PUBLISH", "skipReview": <eligible>}` ([publish reference](https://developer.chrome.com/docs/webstore/api/reference/rest/v2/publishers.items/publish)). If the store rejects `skipReview`, the job resubmits for normal review.

**Skip review** ([Chrome docs](https://developer.chrome.com/docs/webstore/skip-review)) applies only when all of this holds: `declarativeNetRequest` is a required permission; only files listed in `rule_resources` changed; every added, changed or removed rule is a *safe* rule (`block`, `allow`, `allowAllRequests`, `upgradeScheme`); no ruleset was added or removed; nothing else changed (the version bump is ignored). Items that were taken down, warned or unpublished never qualify. Such updates usually go live within minutes. Our check compares rules by id, ignoring unknown keys such as `_metadata` (the store ignores them too).

In practice most weekly releases change cosmetic data, scriptlets or the transparency maps as well and therefore go through normal review ("a few days, up to a few weeks"). Releases that only update hostname block lists can take the fast path. To make that more common, the build should keep rule ids stable between releases and keep redirect/header/parameter rules in rulesets that change rarely.

The comparison is made against the previous GitHub release. If that release never reached the store (rejected, still in review), the store compares against an older version and may refuse skip review; the job then falls back to normal review.

### Microsoft Edge Add-ons (Update REST API v1.1)

Setup ([Use the REST API to update an extension](https://learn.microsoft.com/microsoft-edge/extensions/update/api/using-addons-api)):

1. Partner Center > Microsoft Edge > **Publish API** > enable the v1.1 experience > **Create API credentials**. Note the **Client ID** and the **API key**. API keys expire; Partner Center shows the expiry date. Put a reminder in the team calendar and rotate the secret before it expires.
2. Product id: Partner Center > Microsoft Edge > Overview > the extension > Product ID.
3. GitHub environment `edge-addons` with the secrets below.

What the job does (`store-publish.ts edge`): `POST https://api.addons.microsoftedge.microsoft.com/v1/products/{productId}/submissions/draft/package` with the ZIP (headers `Authorization: ApiKey …`, `X-ClientID: …`), poll `…/draft/package/operations/{operationId}`, then `POST …/v1/products/{productId}/submissions` with certification notes, and poll `…/submissions/operations/{operationId}` until the submission is accepted for certification. Certification takes **up to 7 business days** ([Microsoft Learn](https://learn.microsoft.com/microsoft-edge/extensions/publish/publish-extension)). Because certification can take longer than a week, a submission often finds the previous one still in review (`InProgressSubmission`). The job then leaves the package as the draft and ends with a warning; the next weekly run submits a newer version. Edge users therefore receive every release that clears certification, typically every one or two weeks.

The Edge certification notes say that only bundled static rules changed. Edge's developer policy requires declarative rules to be "clearly declared within the extension"; all of Bastion Shield's rules are.

### Secrets and variables

| Name | Kind | Environment | Purpose |
|---|---|---|---|
| `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN` | secret | `chrome-web-store` | OAuth client and refresh token |
| `CWS_PUBLISHER_ID`, `CWS_ITEM_ID` | secret | `chrome-web-store` | which item to update |
| `EDGE_CLIENT_ID`, `EDGE_API_KEY`, `EDGE_PRODUCT_ID` | secret | `edge-addons` | Edge Add-ons API v1.1 |
| `CRX_PRIVATE_KEY` | secret | `crx-signing` | PEM of the self-hosting key (optional) |
| `SELF_HOST_CRX` | variable | repository | `true` enables the self-host job |
| `BASTION_UPDATE_BASE_URL` | variable | `crx-signing` | e.g. `https://updates.example.com/bastion-shield` |

Missing store secrets do not fail the release; the job prints a notice and skips the store.

## Self-hosted CRX and the signing key

Only needed for customers who deploy outside the stores ([DEPLOYMENT-INTUNE.md §7](DEPLOYMENT-INTUNE.md#7-self-hosting-the-extension-advanced)).

**Identity.** The extension id of a self-hosted build is derived from its signing key: the first 128 bits of the SHA-256 of the public key, written with the letters `a`-`p`. The **same key must sign every update** forever; a different key is a different extension, and every customer would have to change their policies. The store-published items have their own store ids and are not affected by this key.

**Generating the key** (once, on an offline or otherwise trusted machine):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out bastion-shield-crx.pem
```

**Custody rules:**

- The key is **never** committed (`.gitignore` excludes `*.pem` and `*.crx`) and never stored on developer laptops.
- Primary copy: Azure Key Vault (HSM-backed where available) or an equivalent, access limited to two named maintainers, access logged.
- CI copy: the `CRX_PRIVATE_KEY` secret in the GitHub environment `crx-signing` with **required reviewers**, so every signing run needs a human approval. The job writes it to a file with mode 600 in the runner's temp directory, deletes it on exit, and does not run `npm ci`: no third-party package code runs while the key is on disk.
- Offline backup: an encrypted copy in two separate secure locations (for example two sealed envelopes with an encrypted USB key in two Bastion safes), checked once a year.
- **Loss** of the key means a new extension id and a policy change at every self-hosting customer. **Compromise** means the same plus a security advisory: whoever holds the key can push updates to self-hosted installs. Rotate immediately and tell customers to block the old id (`ExtensionInstallBlocklist`).

**Packaging.** `tools/package.ts` signs a CRX3 when `BASTION_CRX_KEY` (path to the PEM) is set, adds `update_url` = `<BASTION_UPDATE_BASE_URL>/update.xml` to the CRX's manifest (the store packages never contain it), and writes `update.xml` (gupdate format, `version` equal to the manifest version, `codebase` pointing to the CRX). The `self-host` job unpacks the released Chromium package into `dist/`, runs the packager with the key, and attaches `bastion-shield-<version>.crx` and `update.xml` to the GitHub release; the packager prints the resulting extension id. Locally: `BASTION_CRX_KEY=key.pem BASTION_UPDATE_BASE_URL=https://updates.example.com/bastion-shield npm run package`. Publishing to the update server is a separate, manual or infrastructure-specific step: serve the CRX as `application/x-chrome-extension`, without `X-Content-Type-Options: nosniff`, over HTTPS without authentication.

For local development, the manifest `key` field pins the id of unpacked builds; it contains only the public key.

## Manual release checklist

For a release outside the weekly schedule (urgent filter fix, security fix):

1. Merge the fix to `main`; CI green.
2. **Actions > Release > Run workflow** with *force* = true.
3. Check the GitHub release: assets present, notes plausible, rule budget in the summary.
4. Watch the store jobs; for Chrome, check the Developer Dashboard for review status.
5. For a security fix, consider `minimum_version_required` guidance for customers only once the fixed version is live in both stores, and publish an advisory (SECURITY.md).

## Rolling back

Stores cannot roll back to an older version, and browsers do not downgrade. To undo a bad release, revert the change on `main` and run the release workflow with *force*: the fix ships as a new, higher version. On the Chrome Web Store, an update still in review can be cancelled (`cancelSubmission`); percentage rollout is only available for items with more than 10,000 weekly users. Customers can bridge the gap with `disabledSites` or by disabling a list through policy ([DEPLOYMENT-INTUNE.md §8](DEPLOYMENT-INTUNE.md#8-rollout-updates-and-rollback)). If a release breaks sites widely, tell managed customers about the emergency switch `"protectionEnabled": false`, which turns protection off on every device without uninstalling ([DEPLOYMENT-INTUNE.md §9](DEPLOYMENT-INTUNE.md#9-emergency-switch-protection-off-fleet-wide)); they set it back to `true` once the fixed version is live.
