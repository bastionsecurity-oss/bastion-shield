# Contributing to Bastion Shield

Thank you for helping. Bastion Shield is maintained by Bastion Security GmbH in Zurich and developed in the open. Contributions of every size are welcome: a broken-site report, a filter, a translation fix, code.

By contributing you agree that your contribution is licensed under the GNU General Public License, version 3 or later (GPL-3.0-or-later), the licence of the project. Only contribute work you have the right to license this way; for code or data copied from elsewhere, say where it comes from and under which licence.

Be kind and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/); report unacceptable behaviour to the maintainers through the contact in [SECURITY.md](SECURITY.md).

## Reporting problems

Use the issue forms: **Broken website**, **Missed ad or tracker**, **Feature request**. The extension's "Report a broken site" button fills in most fields for you.

Issues are public. Give the **hostname only** (`www.example.ch`), never full addresses: they often contain session ids, e-mail addresses or order numbers. No screenshots with personal data. Security problems never go into an issue; see [SECURITY.md](SECURITY.md).

## Filter contributions

### Upstream first

Most fixes belong in the list that causes or misses the problem, so that everyone using that list benefits:

| Problem | Report to |
|---|---|
| Generic ad/tracker missed, simple ABP-syntax fix | [EasyList / EasyPrivacy](https://github.com/easylist/easylist) |
| German-, French-, Italian-language site | [EasyList Germany](https://github.com/easylist/easylistgermany), [AdGuard](https://agrd.io/report) (French, includes Liste FR), [EasyList Italy](https://github.com/easylist/easylistitaly) |
| Needs scriptlets or uBO syntax; breakage caused by uBlock filters | [uBlockOrigin/uAssets](https://github.com/uBlockOrigin/uAssets) |
| Problem in a Brave list | [brave/adblock-lists](https://github.com/brave/adblock-lists) |

Follow each project's own rules (uAssets, for example, requires an issue link above every filter and accepts no requests for new lists). Link the upstream issue in our issue so we can follow it.

### The Bastion list (`filters/bastion.txt`)

For Swiss specifics, Bastion customer environments, and urgent fixes until upstream ships them:

1. Open an issue first (or use an existing one).
2. Add the filter in uBlock Origin syntax, in the right section, **appended at the end** of that section.
3. Put a comment with the issue URL on the line above:

   ```
   ! https://github.com/bastionsecurity-ch/bastion-shield/issues/123
   example.ch##.ad-container
   ```

4. Keep it narrow: prefer `example.ch##.ad-slot` over a generic `##.ad-slot`, and `||ads.example.ch^$third-party` over broad patterns.
5. Remove the filter again once the upstream list has the fix (note the upstream link in the pull request).

Test a filter before submitting: paste it into the dashboard's custom filters and reload the page (network and cosmetic filters work there), or add it to `filters/bastion.txt` and run `npm run build`, which reports filters it cannot convert. Scriptlet filters (`##+js(...)`) only work from a list in the package, not from custom filters.

Only sources maintained by uBlock Origin, Brave and Bastion may use `trusted-*` scriptlets and trusted redirect resources. Trust is set per source in `filters/catalog.json`: a trusted list that includes a third-party source marks it `"trusted": false`, and the build then rejects trusted filters from that source ([docs/FILTER-LISTS.md](docs/FILTER-LISTS.md), note 3). The Bastion list may use them, but every trusted scriptlet needs a reviewer's approval.

### New filter lists

See [docs/FILTER-LISTS.md §9](docs/FILTER-LISTS.md#9-adding-a-list): licence first (no non-commercial licences), then value, rule budget and tests.

## Code

### Setup

```sh
npm ci
npm run build
npm run validate        # loads a copy of dist/ in Chromium, records the regexes Chromium rejects
npm run build:offline   # rebuilds from the cached lists without those regexes
npm test
npm run test:e2e
```

Without the validate pass and the rebuild, e2e test `01-load` fails when the lists contain regexes over Chromium's RE2 memory limit; CI runs the same three steps.

Node.js 22.18 or newer (CI: Node 24). Load `dist/` as an unpacked extension for manual testing (see the [README](README.md#quick-start-development)).

### Style

- **TypeScript, ESM, strict.** Node runs `.ts` files directly through type stripping, so use only erasable syntax: no `enum`, no `namespace`, no parameter properties, no `import =`. Import local files **with** the `.ts` extension and use `import type` for type-only imports.
- Every source file starts with a short header comment, `// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors` and `// SPDX-License-Identifier: GPL-3.0-or-later` (use the file format's comment syntax). Preserve upstream copyright and licence notices in adapted code. Project and creator credits are in [AUTHORS.md](AUTHORS.md).
- Comments explain *why*, not *what*.
- The architecture contract is [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) with `src/shared/constants.ts`, `src/shared/types.ts` and `src/compiler/types.ts`. Change the document and the code together, never one without the other.
- **Performance:** nothing may run per network request; content scripts must stay small and do nothing on pages that need nothing; let the service worker sleep.
- **Robustness:** never throw in hot paths (message handlers, content scripts, request listeners). Every `chrome.*` call that can fail is guarded and its failure logged, not propagated to the page.
- **No remote code, no network requests.** All code ships in the package (store policies require it, and our privacy promise depends on it). No telemetry of any kind. New permissions need a reason in the pull request and an entry in [docs/PRIVACY.md](docs/PRIVACY.md).
- **Dependencies:** the extension has no runtime npm dependencies. Build-time dependencies need a good reason. Vendored third-party code lives in `vendor/` at a pinned commit (`vendor/VENDOR.json`) and is updated deliberately.
- **UI text** exists in `en`, `de`, `fr` and `it` (`src/_locales/`). German uses Swiss orthography: "ss" never "ß", «Guillemets», apostrophe as thousands separator (100'000). French and Italian likewise in Swiss usage.

### Tests

- `npm test`: unit tests with `node:test` (compiler option mappings, merging, cosmetic and scriptlet extraction, hostname helpers, policy merging). New compiler behaviour needs a test.
- `npm run test:e2e`: Playwright with Chromium loads a copy of the unpacked build (which validates all network rules) and checks blocking, cosmetic hiding, scriptlets, the warning page, per-site switches, popup and dashboard on local fixture pages.
- `node .github/scripts/check-policy.ts`: managed-policy schema and examples.
- `npm run bench`: comparison with Brave on real sites (manual, results go into [docs/PARITY.md](docs/PARITY.md)).

### Pull requests

- One topic per pull request; link the issue.
- CI must be green (type-check, unit tests, policy checks, build, rule budget, e2e).
- Describe user-visible changes; include screenshots of UI changes (without personal data).
- Commit messages: imperative mood, short subject line (`Fix cosmetic filtering in about:blank frames`), details in the body.
