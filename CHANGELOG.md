# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- `watermelon backup` writes the copy readable only by you (mode 0600 on Unix), like the
  upgrade backup. It holds the sealed secret keys and the admin password hash; before, it got
  the default permissions.

### Windows (no Windows release yet)
- Secrets are protected with access lists: the data directory, database, master keyfile,
  upgrade backups and exported secret keys are created so that only the account running
  watermelon can access them, ignoring permissive parents such as `C:\ProgramData`.
  `init` also restricts an existing data directory that other users can access, so that
  files created in it (SQLite's `-wal` and `-shm`) are private. A master keyfile other users
  can access is refused, as on Unix, with the `icacls` commands that fix it; LocalSystem and
  Administrators don't count, like root.
- Jobs leave a file alone while another process still has it open for writing, such as an
  SFTP upload that stalled, and pick it up once it's released, without logging it as failed.
  While a file is processed, others can read it but not change or delete it.
- Moving sources to `processed/` or `failed/` and publishing outputs never replace an
  existing file, also on filesystems without hard links, and work across drives.
- Files marked hidden or system (`Thumbs.db`, `desktop.ini`) are ignored like dotfiles.
- Job folders: drive-letter and UNC paths; folders that differ only in case count as the
  same folder; the job form shows Windows examples.
- Retrying a failed file refuses names with `:`, which on Windows could point outside the
  failed folder (`C:name`) or at an alternate data stream.

## [0.2.0] - 2026-11-25

### Keys
- Anonymous keys: a key can belong to no customer, for example your own signing key used by
  several customers' jobs. Generate or import them from the Keys page ("No customer") or with
  `key gen` / `key import` without `--customer`. They show as "anonymous" and have their own
  filter on the Keys page.
- Keys can be generated and imported from the Keys page, choosing the customer in the dialog.
- The database is upgraded automatically on first start (schema v4), and 0.1.0 can't open the
  upgraded one. Before upgrading, the old database is copied to `watermelon.db.schema-v3.bak`
  next to it (mode 0600); to go back to 0.1.0, stop the service and restore that copy.

### Web UI
- New look, built on a design system: design tokens (colour roles, type, spacing) in one file,
  reusable components in `src/ui`, and a living style guide at `/styleguide` in debug builds
  (release builds don't include it). See `docs/design-system.md`.
- The stylesheet is bundled and minified at build time (lightningcss); every static file's URL
  carries a hash of its content.
- Sidebar navigation, a search box for the audit log on every page, and a dashboard with stat
  cards, a "Needs attention" list and recent activity.
- Keys as rich rows with the fingerprint, status and capabilities, filters (key pairs, public
  only, needs attention, revoked) and search. A key's page shows the full fingerprint.
- New customers, key generation and key import open in dialogs from the page or panel header.
- Revoking or deleting a key and deleting a job ask in a dialog first. Without JavaScript, a
  tick box does the same.
- The outcome of a form shows as a toast in the corner. Slow actions such as generating an RSA
  key show a spinner while they run.
- The job form is in numbered steps, and a rejected job shows the reason next to the field to
  blame.
- Table headings stay in view while scrolling; long audit details show three lines and the rest
  on demand.
- The audit log's address leaves out empty filters (`/audit?q=acme`, not
  `/audit?q=acme&period=&from=…`).
- A key's page: details across the top, the public and secret exports side by side with their
  buttons level, and revoke/delete below.
- Copy buttons for fingerprints (where the browser allows clipboard access).
- Light and dark themes: follows the system, or pick one in the sidebar or in Settings
  (remembered per browser in a cookie).
- Geist and JetBrains Mono fonts and Lucide icons, served from the binary.
- Form hints are no longer read out as part of a field's name by screen readers.
- The new look needs a browser from 2024 or later (`light-dark()`, `:has()`, popovers); older
  browsers get the light theme. Confirmation dialogs without JavaScript need one from 2025.

### Tests
- End-to-end tests of the core flows in a real browser (Playwright): logging in and out,
  customers, generating, importing and revoking keys, an encrypt and decrypt round trip with a
  failed file and its retry, the audit log's filters and CSV export, the theme switch, and the
  confirmation dialogs with and without JavaScript.

## [0.1.0] - 2026-11-24

The first release: key management and folder encryption/decryption jobs with a web UI, as a
single binary.

### Keys
- Generate v4 Ed25519/Cv25519 or RSA-4096 keys, readable by GnuPG 2.2 and later.
- Import public and secret keys (armored or binary); passphrase-protected secret keys are
  unlocked once and re-encrypted under the master key.
- Re-importing a partner's key updates it (new expiry date, revocation); known revocations are
  never dropped.
- Export public keys; export secret keys under a new passphrase.
- Revoke our own keys, with a reason. Jobs that encrypt to or sign with a revoked or expired
  key pause themselves.
- Soft delete; keys used by jobs can't be deleted.

### Jobs
- Encrypt jobs (several recipients, optional signing, binary or armored, SEIPD v1 or v2) and
  decrypt jobs (several keys, signature policy ignore/warn/require).
- Polling with a stability check; partial uploads (`*.part`, `*.filepart`, `*.tmp`, dotfiles, …)
  are ignored.
- Streaming with bounded memory; output appears atomically and never overwrites a file;
  tampered input never produces output.
- Sources move to `processed/` or `failed/`; failed files can be retried from the UI. Temp files
  left behind by a crash are cleaned up.

### Web UI and operations
- `watermelon serve`: web UI and job engine in one process. Dashboard, customers, keys, jobs,
  filterable audit log, settings. Works without JavaScript.
- Single admin password (Argon2id); HttpOnly SameSite=Strict sessions with idle and absolute
  timeouts; CSRF tokens and Origin checks; login rate limiting; strict CSP.
- Built-in HTTPS (rustls) with certificate reload on SIGHUP, or run behind a reverse proxy.
- Text or JSON logs; `/healthz`.
- Append-only audit log of every change, login and processed file. Filter it by time range,
  actor, action, customer and job, search subjects and details, and export matches as CSV.
- `watermelon backup` for consistent snapshots (the master key is deliberately excluded).
- Docker image, systemd unit, deployment guide.
- Release binaries for Linux (x86_64, arm64) and macOS (Apple silicon, Intel), a Homebrew tap
  (`brew install tarannum22/tap/watermelon-pgp`, with `brew services` support) and a website.

### Known issues
- Two advisories in rPGP's dependencies have no usable fix yet (RUSTSEC-2023-0071 in `rsa`,
  RUSTSEC-2026-0387 in `crypto-bigint`); both are timing side channels we consider low risk
  here. See the README.
- GnuPG 2.4.8 with libgcrypt 1.12.0 (Ubuntu 26.04) can't import most passphrase-protected
  Curve25519 secret keys exported by watermelon. See the README.
