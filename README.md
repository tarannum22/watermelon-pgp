<p align="center">
  <img src="watermelon-pgp.svg" alt="watermelon-pgp logo" width="160" height="160">
</p>

# watermelon-pgp

A self-hosted, single-binary tool to manage OpenPGP keys and run folder jobs that encrypt or
decrypt files: the glue between your customers' keys and the folders your SFTP transfers read
from and write to.

> **Status: 0.1, the first release.** Everything planned for v1 works and is tested, including
> against GnuPG 2.2–2.5; expect rough edges. See [DESIGN.md](DESIGN.md) for the decisions behind
> it and [CHANGELOG.md](CHANGELOG.md) for what's in each release.

## Features

- **Keys per customer.** Generate (Ed25519/Cv25519 or RSA-4096, readable by GnuPG 2.2+),
  import the keys customers send you (public or secret, armored or binary), export public keys,
  export secret keys under a new passphrase, revoke, delete. Expired, expiring and revoked keys
  are flagged.
- **Folder jobs.** Watch a folder and encrypt every file dropped into it for one or more
  recipients (optionally signed), or decrypt incoming files (optionally requiring a valid
  signature). Files are picked up only once fully uploaded, streamed with bounded memory,
  published atomically without overwriting anything, then archived to `processed/` or moved to
  `failed/` with the reason recorded.
- **Web UI.** Dashboard, customers, keys, jobs and a filterable audit log, in one binary with no
  external assets. Every page works without JavaScript.
- **Audit log.** Every change, login, export and processed file (with its SHA-256), append-only.
  Filter by time, who did it, action, customer or job, search names, keys and details, and export
  the result as CSV.
- **Secure by default.** Secret keys encrypted at rest under a master key kept outside the
  database; loopback-only until you configure HTTPS; hardened sessions, CSRF protection, login
  rate limiting, strict CSP.
- **Easy to run.** One process (`watermelon serve`), SQLite, a systemd unit and a Docker image.

## Install

- **Release binaries** for Linux (x86_64, arm64) and macOS (arm64):
  [GitHub releases](https://github.com/tarannum22/watermelon-pgp/releases), with `SHA256SUMS`.
- **Docker:** `docker pull ghcr.io/tarannum22/watermelon-pgp`, or `docker build -t watermelon-pgp .`
- **From source:** Rust 1.89 or later, then `cargo build --release`; the binary is
  `target/release/watermelon`.

To run it as a service, see [docs/deployment.md](docs/deployment.md): systemd, Docker, HTTPS,
the master key, logs, backups and upgrades. All commands and options are in
[docs/cli.md](docs/cli.md).

## Quick start

```sh
watermelon init      # creates ./data: database, master key, admin password (prompted)
watermelon serve     # web UI on http://127.0.0.1:8080, all enabled jobs running
```

Every command works on a **data directory**: `./data` relative to where you run it, unless you
choose another with `--data-dir` or the `WATERMELON_DATA_DIR` environment variable. Use the same
one for every command, e.g. to keep a test setup apart:

```sh
watermelon --data-dir ~/watermelon-demo/data init
watermelon --data-dir ~/watermelon-demo/data serve
# or
export WATERMELON_DATA_DIR=~/watermelon-demo/data
watermelon init && watermelon serve
```

`init` puts the master key (`master.key`) into the data directory too, which is fine for trying
it out. In production keep it elsewhere with `--master-key` / `WATERMELON_MASTER_KEY_FILE`; see
[docs/deployment.md](docs/deployment.md#the-master-key).

Log in, create a customer, generate or import its keys and create a job. Everything can also be
scripted on the command line:

```sh
watermelon customer add ACME
watermelon key gen --customer ACME --uid "ACME Exports <exports@acme.example>"
watermelon key import --customer ACME partner-key.asc
watermelon key list

# Encrypt everything dropped into /srv/sftp/acme/outbox for ACME's key, archive the originals
watermelon job add encrypt --customer ACME --name outbound \
    --input /srv/sftp/acme/outbox --output /srv/sftp/acme/out --recipient <ACME key ID>

watermelon audit
watermelon backup /backups/watermelon.db    # the master key is NOT included: back it up separately
```

Every command and option is explained in the **[command-line reference](docs/cli.md)**;
`watermelon --help` and `watermelon <command> --help` show the same on the terminal.

For scripted setups, `--passphrase-stdin` reads passwords from stdin instead of prompting, and
`WATERMELON_MASTER_KEY` (hex) can supply the master key instead of the keyfile.

## Security model (short version)

- Secret keys are stored encrypted with XChaCha20-Poly1305 under a 256-bit master key that lives
  outside the database. A stolen database alone reveals nothing.
- The master key is checked against the database at startup; a wrong key is refused.
- A keyfile readable by other users is refused.
- The web UI listens on `127.0.0.1` by default. To expose it, serve HTTPS with `--tls-cert` /
  `--tls-key`, or put a TLS-terminating reverse proxy in front and pass `--secure-cookies`.
- One admin password (Argon2id), set on the CLI; there is no web setup page an attacker could
  reach first. Sessions are `HttpOnly`, `SameSite=Strict` cookies that end after 30 minutes idle
  or 12 hours; changing the password ends all other sessions.
- Every form carries a CSRF token, cross-origin form posts are refused, failed logins are
  audited and slowed down per client, and pages are served with a strict Content Security Policy
  (no inline scripts, no framing) and `Cache-Control: no-store`.

## Known issues

- **Two dependency advisories without a fix yet**, both timing side channels inside rPGP's
  dependencies: [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (`rsa`,
  "Marvin attack", RSA keys) and [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387)
  (`crypto-bigint`, NIST/brainpool/secp256k1/X448 keys). The newest rPGP release still uses the
  affected versions. Exploiting them needs an attacker who can trigger many private-key
  operations and time each one precisely; folder jobs run on a polling schedule and give no such
  feedback, so we consider the risk low. Prefer Curve25519 keys (the default) where partners
  support them. The reasoning is in [`.cargo/audit.toml`](.cargo/audit.toml); the exceptions
  go away as soon as rPGP updates.

- **Ubuntu 26.04 (GnuPG 2.4.8 with libgcrypt 1.12.0) cannot import most passphrase-protected
  Curve25519 secret keys exported by watermelon** ("Bad passphrase" when the key is used). The
  same exports work with libgcrypt 1.11 and 1.12.4, and on 1.12.0 RSA exports, public keys and
  encrypted files are unaffected. This looks like the elliptic-curve regression in libgcrypt
  1.12.0 that later 1.12.x releases fix. Until Ubuntu ships the fix, export an RSA-4096 key for
  partners who need a secret key on that platform. CI reports this case as a known issue
  instead of a failure.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```sh
cargo test --release   # includes GnuPG interop tests when `gpg` is installed
```

CI runs the tests on Linux and macOS against several GnuPG versions, checks formatting, clippy,
the minimum Rust version and known-vulnerable dependencies, and smoke-tests the Docker image.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
