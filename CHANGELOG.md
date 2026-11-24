# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Web UI
- New look, built on a design system: design tokens (colour roles, type, spacing) in one file,
  reusable components in `src/ui`, and a living style guide at `/design` in evaluation builds
  (`--features evaluation`; release builds don't include it). See `docs/design-system.md`.
- Sidebar navigation, a search box for the audit log on every page, and a dashboard with stat
  cards, a "Needs attention" list and recent activity.
- Keys as rich rows with the fingerprint, status and capabilities, filters (key pairs, public
  only, needs attention, revoked) and search. A key's page shows the full fingerprint.
- New customers are created in a dialog opened from the page header.
- Copy buttons for fingerprints (where the browser allows clipboard access).
- Light and dark themes: follows the system, or pick one in the sidebar or in Settings
  (remembered per browser in a cookie).
- Geist and JetBrains Mono fonts and Lucide icons, served from the binary.
- Form hints are no longer read out as part of a field's name by screen readers.

### Tests
- End-to-end tests of the core flows in a real browser (Playwright): logging in and out,
  customers, generating, importing and revoking keys, an encrypt and decrypt round trip with a
  failed file and its retry, the audit log's filters and CSV export, and the theme switch.

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
