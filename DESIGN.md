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
config export/import.

## Shape

- Rust, Cargo workspace:
  - `watermelon-pgp-core` — crypto wrapper (rPGP), key store, master-key envelope, SQLite schema, audit log.
  - `watermelon-pgp-jobs` — polling job engine.
  - `watermelon-pgp-web` — the web UI (axum, maud templates, vendored htmx).
  - `watermelon-pgp` — the `watermelonpgp` binary: CLI, and `serve` for web UI + job engine.
- Single binary, embedded assets. Linux primary, Windows Server (x86_64, as a native
  service), macOS for development. What differs between them stays behind small `platform`
  modules (access lists, file locking and attributes, moves).
- Storage: SQLite in the data dir. Process-level settings (bind address, data dir, master key
  path, TLS cert/key, log format) are CLI flags, each with a `WATERMELONPGP_*` environment variable.
  Everything else lives in the DB and is managed through the GUI.
  - *Changed from the original plan of a TOML config file:* every deployment target already has
    a natural way to set environment variables (systemd `EnvironmentFile=`, Docker `-e`/`--env-file`),
    and one mechanism is easier to document and reason about than two with precedence rules.
- Web: axum + server-rendered templates + htmx. No JS build step.
- Runs in the foreground (`watermelonpgp serve`); a sandboxed systemd unit
  (`contrib/systemd/`) and a Docker image (non-root, uid 10001) are provided, see
  `docs/deployment.md`. SIGTERM lets running jobs finish their current file; SIGHUP reloads
  the TLS certificate.
- On Windows, `watermelonpgp service install` registers `serve` as a native service (the
  `windows-service` crate) running as the virtual account `NT SERVICE\watermelonpgp`, which it
  makes the owner of the data directory and master key. Stop, Preshutdown and Shutdown take
  the same path as SIGTERM; the ParamChange control reloads the TLS certificate. Settings go into the
  service's command line as flags, so there is still one configuration mechanism.
- License: MIT OR Apache-2.0.

## Domain

- **Customer** — first-class grouping. Jobs belong to a customer, and so do keys unless they are
  *anonymous* (belong to no customer, e.g. our own signing key shared by jobs). A customer that still
  owns keys or jobs cannot be deleted.
- **Key** — an OpenPGP certificate, public-only or with secret material.
- **Job** — watches an input folder and processes files into an output folder.
- **Audit event** — append-only record of everything that happens.

## Security

- **Auth:** single admin password, Argon2id hash. Created by `watermelonpgp init` on the CLI — there
  is no web first-run setup page (a fresh exposed instance could be claimed by anyone).
- **Network:** binds `127.0.0.1` by default; exposing it is explicit config. Optional built-in TLS
  (rustls) when a cert/key is configured, otherwise run behind a reverse proxy. Secure cookie
  sessions, CSRF protection, login rate limiting, security headers (CSP etc.).
- **Web sessions:** random 256-bit tokens in an `HttpOnly`, `SameSite=Strict` cookie (`Secure`
  with `--secure-cookies`); the server keeps only their SHA-256, in memory, so a restart logs
  everyone out. 30 minutes idle timeout, 12 hours absolute; auto-refreshing panels don't count
  as activity. A password change ends all other sessions.
- **CSRF:** a per-session token in every form, plus refusing state-changing requests whose
  `Origin` doesn't match `Host` or whose `Sec-Fetch-Site` is `cross-site`.
- **Login rate limiting:** per client address, five free attempts, then a wait that doubles with
  each failure up to 15 minutes. Behind a reverse proxy all clients share the proxy's address,
  which makes the limit global; that is acceptable with a single admin account.
- **Browser hardening:** strict CSP (`script-src 'self'`, no inline scripts or styles, no
  framing), `nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` on pages. htmx is
  vendored and configured without `eval` and with its localStorage history cache disabled, so
  pages showing key data are never persisted by the browser.
- **Private keys at rest:** envelope encryption. Every secret key is stored encrypted
  (XChaCha20-Poly1305) under a 256-bit **master key** loaded at startup from a `0600` keyfile or
  an environment variable. Jobs therefore run unattended across restarts; stealing the DB alone
  yields nothing. Sealed mode and OS keyring / KMS backends can come later behind the same
  abstraction.
  On Windows a keyfile counts as private when its owner is the current user, LocalSystem,
  Administrators or a Windows service account (`NT SERVICE\…`), and its access list allows
  no one else: any other owner could change the access list.
- **Imported secret keys:** the passphrase is asked once, the key is unlocked and re-wrapped under
  the master key. Their passphrase is not stored.
- **Export:** public keys freely. Secret-key export requires choosing a new passphrase and is audited.
- **Backups:** `watermelonpgp backup` writes a consistent SQLite snapshot. The master key is
  deliberately excluded and must be backed up separately; `watermelonpgp init` warns about this once.

## OpenPGP

- Library: **rPGP** (`pgp` crate) — pure Rust, MIT/Apache-2.0, independently audited, streams
  encryption and decryption. Wrapped in our own `crypto` module so a swap stays possible.
- Compatibility-first defaults, since many partners run GnuPG 2.2/2.4:
  - Generated keys: **v4**, Ed25519 (sign) + Cv25519 (encrypt) by default; RSA-4096 optional.
  - Encryption: **SEIPD v1** by default; SEIPD v2 (AEAD) is a per-job opt-in.
- Key operations in v1: generate, import (public and secret), export, details (fingerprint, user
  IDs, expiry, subkeys), revoke, expiry warnings (30 days).
- **Revocation:** our own keys are revoked with a self-signed key revocation signature carrying a
  reason; partners learn about it from the re-exported public key. A revoked key still decrypts
  old files. Re-importing a partner's key updates the stored copy (new expiry, revocation), but
  revocations already known are always kept, so a stale copy can never un-revoke a key. Keys we
  hold the secret for are only changed here, never by import.
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
  patterns (`*.part`, `*.filepart`, `*.tmp`, `*.crdownload`, `*.partial`, dotfiles; on Windows
  also files with the hidden or system attribute). Only regular files directly in the input
  folder are considered; subfolders and symlinks are skipped. On Windows a file another process
  still has open for writing (an SFTP upload that stalled) is skipped when processing would
  start, without an audit entry, and tried again later; while a file is processed, others can
  read it but not change or delete it.
- **Processing:** streamed (bounded memory, multi-GB files). Output is written to a hidden temp file
  inside the output folder, fsynced, verified, then atomically renamed into place. SEIPD v1 input
  uses rPGP's streaming read mode; unauthenticated plaintext only ever lands in the temp file, which
  is deleted if the integrity check or signature verification fails.
- **After success:** source moves to the job's `processed/` folder (default) or is deleted.
  Moves never replace an existing file (a numbered name is used instead) and work across
  filesystems; on Windows the no-replace move is a single atomic call.
- **After failure:** source moves to the job's `failed/` folder; the error is in the audit log and on
  the job page. No automatic retries; retry is a button or moving the file back.
- **Crash recovery:** a crash mid-file leaves at most a hidden `.<name>.<pid>-<n>.watermelon-tmp`
  file in the output folder; the source stays in the input folder and is processed again.
  Temp files untouched for 15 minutes are removed on the next pass (by age, not PID: in a
  container the PID is the same after every restart).
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

- `/healthz` endpoint (no login; checks the database).
- Logs to stderr or a file (`--log-file`; the Windows service has no console), text or JSON
  (`--log-format`), level via `WATERMELONPGP_LOG`: page requests, job passes that did something,
  pauses and errors. The audit log remains the record of who did what.
- TLS: rustls with the `ring` provider (no C/C++ build dependencies beyond a C compiler).
- CLI: `watermelonpgp init`, `watermelonpgp serve`, `watermelonpgp backup`, plus key and job commands.

## Quality gates (CI)

- GnuPG interop both directions: Ed25519/Cv25519 and RSA-4096, binary and armored, signed and unsigned.
- Large-file streaming tests, crash-during-write tests, tampered-file tests (a tampered SEIPD v1
  file must produce no output and land in `failed/`).
- The test suite, GnuPG interop included, runs on Linux, macOS and Windows (Server 2025,
  GnuPG's own Windows build, the one Gpg4win bundles), and Clippy runs on Linux and Windows,
  so Windows-only code is linted.
- Minimum supported Rust version (1.89) builds; `cargo audit` finds no known-vulnerable
  dependencies; the Docker image builds and passes a smoke test.

## Milestones

1. ✅ **Core + CLI** — crypto wrapper, key store with master-key envelope, SQLite schema, audit log;
   CLI key commands (`gen` / `import` / `export` / `list`).
2. ✅ **Job engine** — polling, stability check, encrypt/decrypt pipeline, processed/failed handling.
3. ✅ **Web UI** — auth, customers, keys, jobs, audit view, dashboard.
4. ✅ **Hardening & release** — TLS, security headers, interop CI, Docker image, docs, first release.
