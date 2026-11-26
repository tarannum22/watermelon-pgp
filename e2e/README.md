# End-to-end tests

The core user flows, in a real browser (Playwright, Chromium) against a real `watermelonpgp`
binary. They complement the Rust tests in `crates/watermelon-pgp-web/tests`, which send
requests straight into the router: these also cover htmx, the JavaScript, the CSS that hides
and shows parts of forms, file downloads, and the job engine processing real files.

```sh
cargo build                         # from the repository root (debug: has the style guide)
cd e2e
npm ci
npx playwright install chromium
npm test                            # all flows
npm run screenshots                 # every page, light and dark, into screenshots/
WEBSITE_IMAGE=ghcr.io/tarannum22/watermelon-pgp:X.Y.Z npm run website   # site/img/, see below
npm run report                      # the HTML report of the last run
```

`WATERMELONPGP_BIN` picks another binary (relative to the repository root), `E2E_PORT` another port
(default 18080).

## How it works

- `support/server.ts` wipes `.run/`, runs `watermelonpgp init` there and starts `watermelonpgp serve`.
  Playwright starts it before the tests and stops it afterwards.
- `tests/login.setup.ts` logs in once; the other tests reuse that session.
- Tests share one server, so they run one at a time and make their own data with unique names
  (`unique()` in `support/app.ts`). They don't depend on each other.
- Job tests use folders under `.run/folders/` and wait for the job engine to process the files.

| Test | Flow |
|---|---|
| `auth.spec.ts` | Login required, wrong password refused, log in and out |
| `keys.spec.ts` | Generate a key pair and download its public key; import a partner's key by pasting it; key list filters and search; revoking asks in a dialog; without JavaScript, deleting needs the tick box |
| `jobs.spec.ts` | Encrypt a dropped file and decrypt it again; a failed file shows up and can be retried; disable and enable; a rejected job form keeps its input |
| `audit.spec.ts` | Search from the top bar, live filters, removable filter chips, CSV export |
| `theme.spec.ts` | The theme switch is remembered, also on the login page |
| `design.spec.ts` | The style guide renders; no page triggers a Content-Security-Policy violation; the new-customer dialog opens, keeps focus inside, and closes |

## The website's screenshots

`npm run website` retakes the screenshots in `site/img/` for a release (docs/releasing.md,
"Website"). It needs Docker and the release's image in `WEBSITE_IMAGE`; `WEBSITE_VERSION` sets
the version they must show for an image whose tag isn't `X.Y.Z` (say, `docker build -t
watermelon-pgp:dev .` from the repository root, to try a UI change), `WEBSITE_PORT` another port
(default 18090).

- `playwright.website.config.ts`: its own config, so `npm test` never runs it.
- `website/demo.ts` starts the image as a container named `watermelonpgp-website-demo`, with the
  job folders in a tmpfs at `/srv/sftp`. Through the CLI it adds three customers, our keys and
  the partners' (made in a second data directory in the container, one of them revoked), four
  jobs, and files: processed ones, and one that isn't OpenPGP, so the decrypt job shows a failed
  file. Then it runs `serve`; the container and its volume are removed when Playwright stops it.
- `website/screenshots.spec.ts` takes the screenshots and checks the version in the sidebar.
- `website/social-card.html` is the link preview's layout, around `dashboard-dark.png`.
