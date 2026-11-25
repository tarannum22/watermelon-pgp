# Command-line reference

```
watermelon [GLOBAL OPTIONS] <COMMAND> [OPTIONS]
```

Everything the web UI does can also be done here, which is handy for scripting and for setting
things up before the UI is reachable. `watermelon --help` and `watermelon <command> --help` show
the same information as this page.

- [Global options](#global-options)
- [Referring to keys and jobs](#referring-to-keys-and-jobs)
- [Setup and running](#setup-and-running): `init`, `serve`, `run`, `passwd`
- [Windows service](#windows-service): `service install`, `service uninstall`
- [Customers](#customers): `customer add`, `customer list`
- [Keys](#keys): `key gen`, `key import`, `key list`, `key export`, `key revoke`, `key delete`
- [Jobs](#jobs): `job add encrypt`, `job add decrypt`, `job list`, `job show`, `job enable`,
  `job disable`, `job delete`, `job run-once`
- [Audit log and backups](#audit-log-and-backups): `audit`, `backup`
- [Scripting](#scripting)

## Global options

These work with every command, before or after the command name
(`watermelon --data-dir X init` and `watermelon init --data-dir X` are the same). Each has an
environment variable, which is the easiest way to set it once for a shell, a systemd unit or a
container.

| Option | Environment variable | Default | Meaning |
|---|---|---|---|
| `--data-dir <dir>` | `WATERMELON_DATA_DIR` | `data` (relative to the current directory) | Where the database lives. Use the same one for every command. |
| `--master-key <file>` | `WATERMELON_MASTER_KEY_FILE` | `<data-dir>/master.key` | The master key file. Must be readable only by its owner. |
| | `WATERMELON_MASTER_KEY` | | The master key itself (64 hex characters), instead of a file. Wins over `--master-key`. |
| `--passphrase-stdin` | | off | Read the password or passphrase from the first line of stdin instead of prompting. For scripts. |
| `--log-format <text\|json>` | `WATERMELON_LOG_FORMAT` | `text` | Log format of `serve` and `run`. |
| | `WATERMELON_LOG` | `info` | Log level of `serve` and `run`: `error`, `warn`, `info`, `debug`. |
| `--log-file <file>` | `WATERMELON_LOG_FILE` | stderr; `<data-dir>\watermelon.log` for the Windows service | Append the log of `serve` and `run` to this file instead. |
| `-h`, `--help` | | | Help for the command. |
| `-V`, `--version` | | | Print the version. |

## Referring to keys and jobs

- **Keys** can be given as the full fingerprint (40 hex characters, as `key list` prints it) or
  any unique ending of it of at least 8 characters, such as the 16-character key ID:
  `AB12CD34EF567890`. Case doesn't matter.
- **Jobs** can be given by their numeric ID (first column of `job list`) or by name. If two
  customers have a job with the same name, use the ID.
- **Customers** are given by name.

## Setup and running

### `init`

Create a new data directory: the database, the master key and the admin password. Prompts for
the password twice (at least 12 characters).

```sh
watermelon init
watermelon --data-dir /var/lib/watermelon --master-key /etc/watermelon/key/master.key init
```

Refuses to overwrite an existing database or key file. Back up the master key afterwards: without
it the secret keys in the database are unrecoverable, and `backup` does not include it.

### `serve`

Run the web UI and all enabled jobs, until Ctrl-C or SIGTERM. Running jobs finish the file they
are working on before the process exits.

| Option | Environment variable | Default | Meaning |
|---|---|---|---|
| `--bind <address:port>` | `WATERMELON_BIND` | `127.0.0.1:8080` | Where to listen. Only this machine can connect by default. |
| `--tls-cert <file>` | `WATERMELON_TLS_CERT` | | Serve HTTPS with this PEM certificate chain. Needs `--tls-key`. |
| `--tls-key <file>` | `WATERMELON_TLS_KEY` | | The PEM private key for `--tls-cert`. |
| `--secure-cookies` | `WATERMELON_SECURE_COOKIES` | off | Mark the login cookie HTTPS-only. Set it when a reverse proxy terminates HTTPS; implied by `--tls-cert`. |
| `--workers <n>` | | number of CPUs | How many jobs may process files at the same time. Files within one job are always processed one after another. |

```sh
watermelon serve
watermelon serve --bind 0.0.0.0:8443 --tls-cert fullchain.pem --tls-key privkey.pem
```

Send SIGHUP (`systemctl reload watermelon`) to reload a renewed TLS certificate without a
restart; for the Windows service, `sc.exe control watermelon paramchange`. See
[deployment.md](deployment.md) for running it as a service.

### `run`

Like `serve`, without the web UI: runs all enabled jobs until Ctrl-C or SIGTERM. Takes
`--workers`. Use either `serve` or `run`, not both at once.

### `passwd`

Change the admin password of the web UI. Prompts for the new password twice. Doesn't ask for the
old one: whoever can run this command on the server already has full access to the data.
Users already logged in to the web UI stay logged in until they log out or their session expires.

## Windows service

### `service install`

Install `serve` as a Windows service, from an elevated (administrator) PowerShell, after `init`.
It takes the options of [`serve`](#serve), `--data-dir`, `--master-key`, `--log-format` and
`--log-file`, from the command line or their environment variables, and stores them in the
service's command line with absolute paths, so put `watermelon.exe` where it will stay
(e.g. `C:\Program Files\WatermelonPGP`) before installing.

| Option | Default | Meaning |
|---|---|---|
| `--name <name>` | `watermelon` | Service name. |

```powershell
watermelon --data-dir C:\ProgramData\WatermelonPGP init
watermelon --data-dir C:\ProgramData\WatermelonPGP service install --bind 127.0.0.1:8080
Start-Service watermelon
```

- The service starts with Windows, and is restarted if it fails (after 5 seconds, twice, then
  every minute).
- It runs as the virtual account `NT SERVICE\<name>`, which needs no password. `install` makes
  that account the owner of the data directory, everything in it and the master keyfile, and
  lets only it, LocalSystem and Administrators access them. Administrators can still run
  commands such as `backup` on the data directory.
- Give `NT SERVICE\<name>` access to the job folders and to any TLS certificate and key yourself.
- The log goes to `<data-dir>\watermelon.log` unless `--log-file` says otherwise.
- `Stop-Service watermelon` lets running jobs finish their current file before the service
  stops. `sc.exe control watermelon paramchange` reloads the TLS certificate.
- To change a setting, uninstall and install again.
- The master key must be in a file: `install` refuses `WATERMELON_MASTER_KEY`.

### `service uninstall`

Stop the service if it runs, waiting while jobs finish their current file, then remove it. Takes
`--name`. The data directory and master key stay as they are, accessible to Administrators.

## Customers

Every job belongs to a customer. Keys usually do too, but a key can also be **anonymous**:
it belongs to no customer (for example your own signing key that several customers' jobs use).

### `customer add <name>`

```sh
watermelon customer add ACME
```

Names must be unique.

### `customer list`

All customers with their number of keys.

## Keys

### `key gen`

Generate a new key pair, for one of your customers or as an anonymous key.

| Option | Default | Meaning |
|---|---|---|
| `--customer <name>` | none: anonymous | The customer the key belongs to. Leave it out for an anonymous key. |
| `--uid <user ID>` | required | Name and e-mail shown to partners, e.g. `"ACME Exports <exports@acme.example>"`. |
| `--algorithm <curve25519\|rsa4096>` | `curve25519` | `curve25519` (Ed25519 for signing, Cv25519 for encryption) is recommended. `rsa4096` for partners whose software can't handle it; it takes a few seconds to generate. Both work with GnuPG 2.2 and later. |

```sh
watermelon key gen --customer ACME --uid "ACME Exports <exports@acme.example>"
watermelon key gen --uid "Our signing key <pgp@example.com>"   # anonymous
```

### `key import [--customer <name>] <file>`

Import keys from a file, armored (`-----BEGIN PGP ...`) or binary. A file may contain several
keys; either all are imported or none. Without `--customer` they are anonymous keys. A key has
one owner: a key already imported for a customer can't be imported again as anonymous, or for
another customer.

- **Public keys** (a partner's key you encrypt to, or whose signatures you check) are stored as is.
- **Secret keys** protected with a passphrase prompt for it once. They are then re-encrypted under
  the master key, so jobs can use them unattended; the passphrase isn't kept.
- **A key that is already there** is updated from the newer copy, for example when a partner
  extends its expiry date or revokes it. A revocation is never lost, even if you later import an
  older copy.
- Importing the secret key of a public key you already have adds the secret part.

```sh
watermelon key import --customer ACME acme-public.asc
```

### `key list`

All keys: fingerprint, algorithm, customer, expiry, flags (`secret` when you hold the secret key,
`REVOKED`) and user ID. `--customer <name>` shows one customer's keys only.

### `key export <key>`

Print a key, armored, to stdout.

| Option | Meaning |
|---|---|
| `--secret` | Export the secret key instead of the public key. Prompts for a new passphrase (at least 8 characters) that protects the exported file. Recorded in the audit log. |
| `-o`, `--output <file>` | Write to this file instead of stdout. Refuses to overwrite an existing file; secret exports are created readable only by you. |

```sh
watermelon key export AB12CD34EF567890 > acme-public.asc
watermelon key export AB12CD34EF567890 --secret -o acme-secret.asc
```

### `key revoke <key>`

Revoke one of your own keys (one you hold the secret key for). Partners learn about it from the
public key, so export it again and send it to them afterwards. This cannot be undone.

| Option | Default | Meaning |
|---|---|---|
| `--reason <reason>` | `unspecified` | `superseded` (replaced by a new key), `compromised` (the secret key may have leaked), `retired` (no longer used), or `unspecified`. |
| `--comment <text>` | empty | A short explanation stored in the revocation. |

```sh
watermelon key revoke AB12CD34EF567890 --reason superseded --comment "replaced by 99FF..."
watermelon key export AB12CD34EF567890 > acme-public-revoked.asc
```

Jobs that encrypt to or sign with a revoked key pause themselves. A revoked key can still decrypt
files that were encrypted to it before.

### `key delete <key>`

Remove a key from use. It stays in the database so the audit log can still show it. Refused while
a job uses the key: change or delete those jobs first.

## Jobs

A job watches an **input** folder. Every file that lands there is encrypted or decrypted into the
**output** folder; the original then moves to the **processed** folder (or is deleted), or to the
**failed** folder if it couldn't be processed. A file is only picked up once it has stopped
changing, and names ending in `.part`, `.filepart`, `.tmp`, `.crdownload` or `.partial`, as well as
hidden files (a leading dot; on Windows also the hidden or system attribute), are ignored, so
half-uploaded files are left alone. On Windows a file that another program still has open for
writing waits until it's closed.

### `job add encrypt` / `job add decrypt`

Options for both kinds:

| Option | Default | Meaning |
|---|---|---|
| `--customer <name>` | required | The customer the job belongs to. |
| `--name <name>` | required | Job name, unique per customer. |
| `--input <folder>` | required | Folder to watch. Must exist. |
| `--output <folder>` | required | Folder for the results. Must exist. Existing files there are never overwritten. |
| `--processed <folder>` | `<input>/processed` | Where originals go after success. Created if missing. |
| `--delete-processed` | off | Delete originals after success instead of keeping them. |
| `--failed <folder>` | `<input>/failed` | Where files go that couldn't be processed. Created if missing. |
| `--interval <seconds>` | `30` | How often the input folder is checked (at least 5). A file is processed once it is unchanged across two checks, so expect up to two intervals of delay. |

Relative folder paths are turned into absolute ones. All four folders must be different (on
Windows regardless of case). On Windows, folders can be drive paths (`D:\sftp\acme\in`) or UNC
paths (`\\server\share\acme\in`).

**Encrypt jobs** encrypt each file so the recipients can read it, and add `.pgp` to its name.

| Option | Default | Meaning |
|---|---|---|
| `--recipient <key>` | required | Who can decrypt the output. Repeat for several; add one of your own keys if you want to be able to read the files too. |
| `--sign-with <key>` | not signed | Also sign the files with one of your secret keys, so recipients can check they came from you. |
| `--armor` | binary | Text output (`-----BEGIN PGP MESSAGE-----`) with the extension `.asc`. |
| `--extension <ext>` | `.pgp`, or `.asc` with `--armor` | Another extension, e.g. `.gpg`. Must start with a dot. |
| `--seipd-v2` | off | Use the newer RFC 9580 format. Only for partners known to support it; GnuPG 2.4 and older cannot read it. |

```sh
watermelon job add encrypt --customer ACME --name outbound \
    --input /srv/sftp/acme/outbox --output /srv/sftp/acme/out \
    --recipient <ACME's key> --recipient <your own key> --sign-with <your key>
```

**Decrypt jobs** decrypt each file and remove a trailing `.pgp`, `.gpg` or `.asc` from its name.

| Option | Default | Meaning |
|---|---|---|
| `--key <key>` | required | Your secret key to decrypt with. Repeat to try several. |
| `--verify-with <key>` | none | A sender's key whose signatures you accept. Repeat for several. |
| `--verify <ignore\|warn\|require>` | `ignore` | What to do about signatures. `warn` processes unsigned or unverifiable files but notes it in the audit log; `require` sends them to the failed folder. `warn` and `require` need at least one `--verify-with`. |

```sh
watermelon job add decrypt --customer ACME --name inbound \
    --input /srv/sftp/acme/in --output /srv/import/acme \
    --key <your key> --verify-with <ACME's key> --verify require
```

A new job is enabled straight away; it runs while `serve` or `run` is running.

### `job list`

All jobs: ID, customer, name, kind, state (`enabled`, `disabled`, or `PAUSED: <reason>`), input and
output folder.

### `job show <job>`

All settings of one job, its state, last run and last error.

### `job enable <job>` / `job disable <job>`

Start or stop a job. `enable` also resumes a job that paused itself (for example because a
recipient key expired), after checking its keys again; if the problem is still there, it says so.

### `job delete <job>`

Delete a job. Its folders and files are left alone, and its history stays in the audit log.

### `job run-once <job>`

Run one check of the job right now and process what is ready, then exit. Useful for testing a new
job, or for running jobs from cron instead of `serve`/`run`. Waits `--settle <seconds>` (default
2) between two looks at the folder, so files still being written are left alone. The job must be
enabled. Exits with status 1 if any file failed or the job had a problem.

```sh
watermelon job run-once outbound
```

## Audit log and backups

### `audit`

The most recent entries of the audit log, newest first: time, who (`cli`, `admin` for the web UI,
`system` for jobs), action, key and details. `--limit <n>` (default 50) sets how many.

The web UI's audit log page can filter by time (last hour/day/week/month or a date range),
who did it, action, customer and job, and search text across customer and job names, key
fingerprints and user IDs, and the details. Filters are part of the URL, so a filtered view can be
bookmarked, and **Export CSV** downloads exactly the matching events.

### `backup <file>`

Write a consistent copy of the database to `<file>` (which must not exist yet), even while `serve`
is running. **The master key is not included**: back it up separately and keep the two apart.
Restoring is described in [deployment.md](deployment.md#backups-and-restore).

```sh
watermelon backup /backups/watermelon-$(date +%F).db
```

## Scripting

- `--passphrase-stdin` reads the password or passphrase from stdin, so commands that would prompt
  can run unattended:

  ```sh
  printf '%s\n' "$ADMIN_PASSWORD" | watermelon --passphrase-stdin init
  printf '%s\n' "$KEY_PASSPHRASE" | watermelon --passphrase-stdin key import --customer ACME key.asc
  ```

  Commands that ask for a new password read it once instead of twice.
- Commands exit with status 0 on success and non-zero on any error, with the reason on stderr.
- Set `WATERMELON_DATA_DIR` (and `WATERMELON_MASTER_KEY_FILE`) once instead of repeating the
  options.
