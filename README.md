<p align="center">
  <img src="watermelon-pgp.svg" alt="watermelon-pgp logo" width="160" height="160">
</p>

# watermelon-pgp

A self-hosted, single-binary tool to manage OpenPGP keys and run folder jobs that encrypt or
decrypt files: the glue between your customers' keys and the folders your SFTP transfers read
from and write to.

> **Status: early development.** Milestones 1 (key store + CLI), 2 (job engine) and 3 (web UI)
> are done. Hardening and the first release are next. See [DESIGN.md](DESIGN.md) for the full plan.

## What works today

- `watermelon serve`: the web UI plus the job engine in one process.
  - Dashboard with running/paused jobs, files processed and failed in the last 24 hours, keys
    that are expired or expire within 30 days, and recent activity; it refreshes itself.
  - Customers, keys (generate, import by upload or paste, download public, export secret with a
    new passphrase, delete), jobs (create, edit, enable/disable, delete, retry failed files),
    and a filterable, paged audit log.
  - Every page works without JavaScript; htmx (vendored, no CDN) only makes it smoother.
- `watermelon init`: creates the database, a master keyfile (`0600`) and the admin password.
- Customers: `watermelon customer add|list`.
- Keys: `watermelon key gen|import|list|export|delete`.
  - Generated keys are v4 Ed25519/Cv25519 (or RSA-4096), readable by GnuPG 2.2 and later.
  - Imported passphrase-protected secret keys are unlocked once and re-encrypted under the
    master key, so jobs can use them unattended.
  - Secret-key exports always require a new passphrase.
- Every change is recorded in an append-only audit log: `watermelon audit`.
- `watermelon backup <file>` writes a consistent database snapshot. The master key is
  deliberately **not** included, so back it up separately.
- Folder jobs: `watermelon job add encrypt|decrypt`, `job list|show|enable|disable|delete`,
  `job run-once`, and `watermelon run` to run all enabled jobs until Ctrl-C.
  - A file is picked up once it is unchanged across two scans; `*.part`, `*.filepart`, `*.tmp`
    and dotfiles are ignored.
  - Output is streamed into a hidden temp file, synced, and published under its final name
    without ever overwriting an existing file. Tampered input or a missing required signature
    never produces output.
  - Sources move to `processed/` (or are deleted) on success and to `failed/` on failure; every
    file is audited with its SHA-256.
  - A job whose recipient key expires or is revoked pauses itself; keys used by jobs can't be
    deleted.

## Quick start

```sh
cargo build --release
./target/release/watermelon init                 # prompts for the admin password
./target/release/watermelon customer add ACME
./target/release/watermelon key gen --customer ACME --uid "ACME Exports <exports@acme.example>"
./target/release/watermelon key list

# Encrypt everything dropped into ./outbox for ACME, archive the originals
./target/release/watermelon job add encrypt --customer ACME --name outbound \
    --input outbox --output to-sftp --recipient <ACME key ID>

# Web UI on http://127.0.0.1:8080, with all enabled jobs running
./target/release/watermelon serve
```

Everything after `init` can also be done in the web UI. `watermelon run` runs the jobs without
the UI.

For scripted setups, `--passphrase-stdin` reads passwords from stdin instead of prompting, and
`WATERMELON_MASTER_KEY` (hex) can supply the master key instead of the keyfile.

## Security model (short version)

- Secret keys are stored encrypted with XChaCha20-Poly1305 under a 256-bit master key that lives
  outside the database. A stolen database alone reveals nothing.
- The master key is checked against the database at startup; a wrong key is refused.
- A keyfile readable by other users is refused.
- The web UI listens on `127.0.0.1` by default. It speaks plain HTTP: to expose it, put a
  TLS-terminating reverse proxy in front and pass `--secure-cookies`.
- One admin password (Argon2id), set on the CLI; there is no web setup page an attacker could
  reach first. Sessions are `HttpOnly`, `SameSite=Strict` cookies that end after 30 minutes idle
  or 12 hours; changing the password ends all other sessions.
- Every form carries a CSRF token, cross-origin form posts are refused, failed logins are
  audited and slowed down per client, and pages are served with a strict Content Security Policy
  (no inline scripts, no framing) and `Cache-Control: no-store`.

## Known issues

- **Ubuntu 26.04 (GnuPG 2.4.8 with libgcrypt 1.12.0) cannot import most passphrase-protected
  Curve25519 secret keys exported by watermelon** ("Bad passphrase" when the key is used). The
  same exports work with libgcrypt 1.11 and 1.12.4, and on 1.12.0 RSA exports, public keys and
  encrypted files are unaffected. This looks like the elliptic-curve regression in libgcrypt
  1.12.0 that later 1.12.x releases fix. Until Ubuntu ships the fix, export an RSA-4096 key for
  partners who need a secret key on that platform. CI reports this case as a known issue
  instead of a failure.

## Development

```sh
cargo test --release   # includes GnuPG interop tests when `gpg` is installed
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
