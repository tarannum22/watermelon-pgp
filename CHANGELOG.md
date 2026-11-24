# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

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
- Append-only audit log of every change, login and processed file.
- `watermelon backup` for consistent snapshots (the master key is deliberately excluded).
- Docker image, systemd unit, deployment guide.

### Known issues
- Two advisories in rPGP's dependencies have no usable fix yet (RUSTSEC-2023-0071 in `rsa`,
  RUSTSEC-2026-0387 in `crypto-bigint`); both are timing side channels we consider low risk
  here. See the README.
- GnuPG 2.4.8 with libgcrypt 1.12.0 (Ubuntu 26.04) can't import most passphrase-protected
  Curve25519 secret keys exported by watermelon. See the README.
