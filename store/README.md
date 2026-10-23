# Store listings

Everything the Chrome Web Store and Microsoft Edge Add-ons listings need, kept next to the code so text and images change with the product. The extension package itself comes from the GitHub release (`bastion-shield-<version>-chromium.zip` and `-edge.zip`, see [docs/RELEASING.md](../docs/RELEASING.md)).

| Path | What |
|---|---|
| `listing/{en,de,fr,it}.txt` | Detailed description per language (plain text, paste as is) |
| `privacy-practices.md` | Single purpose, permission justifications, remote code, data usage, Edge certification notes, support contacts |
| `images/{en,de,fr,it}/screenshot-*.png` | Five screenshots per language, 1280×800 |
| `images/{en,de,fr,it}/promo-small-440x280.png` | Small promo tile |
| `images/{en,de,fr,it}/promo-marquee-1400x560.png` | Marquee / large promo tile |
| `images/store-icon-128.png` | Store icon, 128×128 |
| `images/edge-logo-300.png` | Edge extension logo, 300×300 |

## Listing fields

| Field | Chrome Web Store | Edge Add-ons |
|---|---|---|
| Name | from the manifest (`extName`) | from the manifest |
| Summary / short description | from the manifest (`extDescription`, per locale) | from the manifest |
| Description | `listing/<lang>.txt` | `listing/<lang>.txt` |
| Category | Make Chrome Yours › **Privacy & Security** | **Productivity** |
| Default language | English (the manifest's `default_locale`) | English |
| Additional languages | German, French, Italian | German, French, Italian |
| Store icon | `images/store-icon-128.png` | `images/edge-logo-300.png` (extension logo) |
| Screenshots | `images/<lang>/screenshot-1…5` | same |
| Small promo tile | `images/<lang>/promo-small-440x280.png` (required) | same (optional) |
| Marquee / large promo tile | `images/<lang>/promo-marquee-1400x560.png` (optional) | same (optional) |
| Official URL / website | `https://bastionsecurity.ch` (after verifying the domain in Google Search Console) | `https://bastionsecurity.ch` |
| Support | `https://github.com/bastionsecurity-oss/bastion-shield/issues` | same, plus `info@bastionsecurity.ch` |
| Privacy | `privacy-practices.md` | `privacy-practices.md` |
| Mature content | No | No |
| Search terms | (none) | en: `ad blocker`, `tracker blocker`, `privacy`, `ClickFix`, `Intune`, `malware protection`, `adblock`; de: `Werbeblocker`, `Trackerblocker`, `Datenschutz`, `ClickFix`, `Intune`, `Malware-Schutz`, `Adblocker` |

## Regenerating the images

The images are real captures of the current build, made by an end-to-end spec that loads `dist/` in Playwright's Chromium:

```sh
npm run build:offline
BASTION_STORE_IMAGES=store/images npm run test:e2e -- 90-store-images
```

Captions live in `test/e2e/specs/90-store-images.spec.ts` (`CAPTIONS`, `TAGLINE`); the spec fails if a caption wraps. The news sites, the organisation «Muster AG» and the ClickFix page are fictional; the 30-day statistics in the overview are generated, every other number comes from the real rules.
