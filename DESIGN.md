# watermelon-pgp — design

A self-hosted, single-binary web tool to manage OpenPGP keys and run folder jobs that
encrypt or decrypt files (typically CSV/PDF customer data dropped for, or picked up by, SFTP).

North star: feature-complete, reliable, secure, audited. This document records the decisions
made for v1 and what is explicitly deferred.

## Scope

**v1:** key management + folder-watch encrypt/decrypt jobs + audit log, behind a web GUI.

**Not v1:** SFTP transfer, multi-user / user management, notifications (webhooks are first after
v1), keyserver/WKD lookup, web of trust, smartcards/HSM, sign-only / verify-only jobs,
filesystem-event watching, sealed (passphrase-unlocked) master key, tamper-evident audit log,
config export/import, Windows as a first-class platform.

## Shape

- Rust, Cargo workspace:
  - `watermelon-pgp-core` — crypto wrapper (rPGP), key store, master-key envelope, SQLite schema, audit log.
  - `watermelon-pgp-jobs` — polling job engine.
  - `watermelon-pgp` — the `watermelon` binary: CLI + web UI.
- Single binary, embedded assets. Linux primary, macOS for development; Windows later, so
  Unix-specific code stays behind a small `platform` module.
- Storage: SQLite in the data dir. A small TOML config / CLI flags hold only process-level
  settings (bind address, data dir, master key path, TLS cert/key). Everything else lives in the
  DB and is managed through the GUI.
- Web: axum + server-rendered templates + htmx. No JS build step.
- Runs in the foreground (`watermelon serve`); systemd and Docker examples are documented.
- License: MIT OR Apache-2.0.

## Domain

- **Customer** — first-class grouping. Keys and jobs belong to a customer. A customer that still
  owns keys or jobs cannot be deleted.
- **Key** — an OpenPGP certificate, public-only or with secret material.
- **Job** — watches an input folder and processes files into an output folder.
- **Audit event** — append-only record of everything that happens.

## Security

- **Auth:** single admin password, Argon2id hash. Created by `watermelon init` on the CLI — there
  is no web first-run setup page (a fresh exposed instance could be claimed by anyone).
- **Network:** binds `127.0.0.1` by default; exposing it is explicit config. Optional built-in TLS
  (rustls) when a cert/key is configured, otherwise run behind a reverse proxy. Secure cookie
  sessions, CSRF protection, login rate limiting, security headers (CSP etc.).
- **Private keys at rest:** envelope encryption. Every secret key is stored encrypted
  (XChaCha20-Poly1305) under a 256-bit **master key** loaded at startup from a `0600` keyfile or
  an environment variable. Jobs therefore run unattended across restarts; stealing the DB alone
  yields nothing. Sealed mode and OS keyring / KMS backends can come later behind the same
  abstraction.
- **Imported secret keys:** the passphrase is asked once, the key is unlocked and re-wrapped under
  the master key. Their passphrase is not stored.
- **Export:** public keys freely. Secret-key export requires choosing a new passphrase and is audited.
- **Backups:** `watermelon backup` writes a consistent SQLite snapshot. The master key is
  deliberately excluded and must be backed up separately; `watermelon init` warns about this once.

## OpenPGP

- Library: **rPGP** (`pgp` crate) — pure Rust, MIT/Apache-2.0, independently audited, streams
  encryption and decryption. Wrapped in our own `crypto` module so a swap stays possible.
- Compatibility-first defaults, since many partners run GnuPG 2.2/2.4:
  - Generated keys: **v4**, Ed25519 (sign) + Cv25519 (encrypt) by default; RSA-4096 optional.
  - Encryption: **SEIPD v1** by default; SEIPD v2 (AEAD) is a per-job opt-in.
- Key operations in v1: generate, import (public and secret), export, details (fingerprint, user
  IDs, expiry, subkeys), revoke, expiry warnings (30 days).
- A key referenced by any job cannot be deleted. Deletion is soft, so audit entries keep resolving.
- An expired or revoked recipient key pauses the job with a visible error.

## Jobs

- **Encrypt:** to one or more recipient keys (the GUI nudges adding an own key), optionally signing
  with one of our secret keys. Binary output with `.pgp` appended by default; armored `.asc` and a
  custom extension (e.g. `.gpg`) are per-job options.
- **Decrypt:** with our secret key, optional signature verification with policy
  `ignore` / `warn` / `require`. Strips a trailing `.pgp` / `.gpg` / `.asc`, otherwise keeps the name.
- **Detection:** polling, per-job interval (default 30 s, minimum 5 s). A file is only picked up
  when it is stable — size and mtime unchanged across two scans — and does not match ignore
  patterns (`*.part`, `*.filepart`, `*.tmp`, `*.crdownload`, `*.partial`, dotfiles). Only regular
  files directly in the input folder are considered; subfolders and symlinks are skipped.
- **Processing:** streamed (bounded memory, multi-GB files). Output is written to a hidden temp file
  inside the output folder, fsynced, verified, then atomically renamed into place. SEIPD v1 input
  uses rPGP's streaming read mode; unauthenticated plaintext only ever lands in the temp file, which
  is deleted if the integrity check or signature verification fails.
- **After success:** source moves to the job's `processed/` folder (default) or is deleted.
- **After failure:** source moves to the job's `failed/` folder; the error is in the audit log and on
  the job page. No automatic retries; retry is a button or moving the file back.
- Existing output files are never overwritten — a name collision is a failure. Publishing uses a
  hard link (atomic, fails if the name exists), falling back to a checked rename on filesystems
  without hard links. Archived sources whose name is taken get a `.1`, `.2`, … suffix.
- **Concurrency:** files within a job are processed sequentially; jobs run in parallel up to a
  global worker cap (default: CPU count).

## Audit

Append-only audit log from v1: every key generate / import / export / delete / revoke, every job
create / edit / enable / disable, every login (success and failure), and every file processed
(input SHA-256, output path, key fingerprints used, result). Kept forever. Filterable GUI view.
Hash-chaining for tamper evidence comes later.

## Operations

- `/healthz` endpoint and structured JSON logs.
- CLI: `watermelon init`, `watermelon serve`, `watermelon backup`, plus key commands.

## Quality gates (CI)

- GnuPG interop both directions: Ed25519/Cv25519 and RSA-4096, binary and armored, signed and unsigned.
- Large-file streaming tests, crash-during-write tests, tampered-file tests (a tampered SEIPD v1
  file must produce no output and land in `failed/`).

## Milestones

1. ✅ **Core + CLI** — crypto wrapper, key store with master-key envelope, SQLite schema, audit log;
   CLI key commands (`gen` / `import` / `export` / `list`).
2. ✅ **Job engine** — polling, stability check, encrypt/decrypt pipeline, processed/failed handling.
3. **Web UI** — auth, customers, keys, jobs, audit view, dashboard.
4. **Hardening & release** — TLS, security headers, interop CI, Docker image, docs, first release.
