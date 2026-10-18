<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

## What and why

<!-- What does this change, and why? Link the issue: "Fixes #123". -->

## Kind of change

- [ ] Filter fix in `filters/bastion.txt` (every new filter has its issue link in the comment above it)
- [ ] Filter list catalog (`filters/catalog.json`): licence checked, docs/FILTER-LISTS.md and THIRD_PARTY_NOTICES.md updated
- [ ] Extension code (service worker, content scripts, UI)
- [ ] Build tools or compiler
- [ ] Managed policy (`policy/`, `src/shared/types.ts`), documentation, CI

## Checks

- [ ] `npm run typecheck` and `npm test` pass
- [ ] `npm run build` passes and the build report shows no new budget or regex warnings
- [ ] `npm run test:e2e` passes, or the change cannot affect the extension at runtime
- [ ] New UI text exists in `en`, `de`, `fr` and `it`, German in Swiss orthography (ss, «Guillemets»)
- [ ] No new permission, remote code or network request (or it is explained below and in docs/PRIVACY.md)
- [ ] For upstreamable filter fixes: also reported to EasyList / uAssets / Brave (link)

## Notes for reviewers

<!-- Anything that needs a closer look, screenshots of UI changes (without personal data). -->

By submitting this pull request I agree that my contribution is licensed under the GPL-3.0-or-later (see CONTRIBUTING.md).
