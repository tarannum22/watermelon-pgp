# End-to-end tests

The core user flows, in a real browser (Playwright, Chromium) against a real `watermelon`
binary. They complement the Rust tests in `crates/watermelon-pgp-web/tests`, which send
requests straight into the router: these also cover htmx, the JavaScript, the CSS that hides
and shows parts of forms, file downloads, and the job engine processing real files.

```sh
cargo build --features evaluation   # from the repository root
cd e2e
npm ci
npx playwright install chromium
npm test                            # all flows
npm run screenshots                 # every page, light and dark, into screenshots/
npm run report                      # the HTML report of the last run
```

`WATERMELON_BIN` picks another binary (relative to the repository root), `E2E_PORT` another port
(default 18080).

## How it works

- `support/server.ts` wipes `.run/`, runs `watermelon init` there and starts `watermelon serve`.
  Playwright starts it before the tests and stops it afterwards.
- `tests/login.setup.ts` logs in once; the other tests reuse that session.
- Tests share one server, so they run one at a time and make their own data with unique names
  (`unique()` in `support/app.ts`). They don't depend on each other.
- Job tests use folders under `.run/folders/` and wait for the job engine to process the files.

| Test | Flow |
|---|---|
| `auth.spec.ts` | Login required, wrong password refused, log in and out |
| `keys.spec.ts` | Generate a key pair and download its public key; import a partner's key by pasting it; key list filters and search; revoking needs confirmation |
| `jobs.spec.ts` | Encrypt a dropped file and decrypt it again; a failed file shows up and can be retried; disable and enable; a rejected job form keeps its input |
| `audit.spec.ts` | Search from the top bar, live filters, removable filter chips, CSV export |
| `theme.spec.ts` | The theme switch is remembered, also on the login page |
| `design.spec.ts` | The style guide renders; no page triggers a Content-Security-Policy violation |
