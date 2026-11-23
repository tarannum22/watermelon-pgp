<p align="center">
  <img src="watermelon-pgp.svg" alt="watermelon-pgp logo" width="160" height="160">
</p>

# watermelon-pgp

A self-hosted, single-binary tool to manage OpenPGP keys and run folder jobs that encrypt or
decrypt files: the glue between your customers' keys and the folders your SFTP transfers read
from and write to.

> **Status: early development.** Milestone 1 (key store + CLI) is done. The job engine and the
> web UI are next. See [DESIGN.md](DESIGN.md) for the full plan.

## What works today

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

## Quick start

```sh
cargo build --release
./target/release/watermelon init                 # prompts for the admin password
./target/release/watermelon customer add ACME
./target/release/watermelon key gen --customer ACME --uid "ACME Exports <exports@acme.example>"
./target/release/watermelon key list
```

For scripted setups, `--passphrase-stdin` reads passwords from stdin instead of prompting, and
`WATERMELON_MASTER_KEY` (hex) can supply the master key instead of the keyfile.

## Security model (short version)

- Secret keys are stored encrypted with XChaCha20-Poly1305 under a 256-bit master key that lives
  outside the database. A stolen database alone reveals nothing.
- The master key is checked against the database at startup; a wrong key is refused.
- A keyfile readable by other users is refused.

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
