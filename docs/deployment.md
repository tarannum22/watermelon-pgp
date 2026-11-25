# Deploying watermelon-pgp

`watermelonpgp serve` is the whole application: the web UI and the job engine in one process.
It needs three things:

- a **data directory** for the SQLite database (`WATERMELONPGP_DATA_DIR`),
- the **master key**, which encrypts every secret key in the database, and
- read/write access to the **job folders** (the folders your SFTP server reads and writes).

Every command-line flag has a `WATERMELONPGP_*` environment variable; `watermelonpgp serve --help`
lists them.

On Linux, run it with [systemd](#systemd) or [Docker](#docker); on Windows, as a
[Windows service](#windows-server).

## The master key

`watermelonpgp init` creates the master key next to the database unless you say otherwise. In
production, keep it **outside** the data directory, so a backup or a stolen copy of one never
contains the other:

- a file: `WATERMELONPGP_MASTER_KEY_FILE=/etc/watermelonpgp/key/master.key`. It must be readable only
  by its owner (`0600` or `0400`); WatermelonPGP refuses a key file other users can read. On
  Windows the same goes for its access list; see
  [the data directory and the master key](#the-data-directory-and-the-master-key).
- or the key itself, hex-encoded, in `WATERMELONPGP_MASTER_KEY` (for secret stores that inject
  environment variables).

Back the master key up once, somewhere safe and separate from the database backups. Without it
the secret keys in the database cannot be recovered.

## systemd

[`contrib/systemd/watermelonpgp.service`](../contrib/systemd/watermelonpgp.service) runs WatermelonPGP as
an unprivileged user with a tight sandbox: it can write only to its state directory and the
job folders you allow.

```sh
sudo useradd --system --home-dir /var/lib/watermelonpgp --shell /usr/sbin/nologin watermelonpgp
sudo install -m 0755 watermelonpgp /usr/local/bin/watermelonpgp
sudo install -d -o watermelonpgp -g watermelonpgp -m 0700 /var/lib/watermelonpgp /etc/watermelonpgp/key
sudo install -m 0640 contrib/systemd/watermelonpgp.env /etc/watermelonpgp/

# Database, master key and admin password
sudo -u watermelonpgp env WATERMELONPGP_DATA_DIR=/var/lib/watermelonpgp \
    WATERMELONPGP_MASTER_KEY_FILE=/etc/watermelonpgp/key/master.key watermelonpgp init

sudo install -m 0644 contrib/systemd/watermelonpgp.service /etc/systemd/system/
sudo systemctl edit watermelonpgp       # allow the job folders, see below
sudo systemctl enable --now watermelonpgp
journalctl -u watermelonpgp -f
```

The sandbox makes the whole file system read-only for the service, so list the job folders:

```ini
# systemctl edit watermelonpgp
[Service]
ReadWritePaths=/srv/sftp
```

Folder permissions: the `watermelonpgp` user needs read/write access to every job's input, output,
`processed/` and `failed/` folders. A common setup is a shared group: add `watermelonpgp` and the
SFTP users to it and make the folders group-writable with the setgid bit
(`chmod 2770`). The unit's `UMask=0027` makes output files group-readable.

Settings live in [`/etc/watermelonpgp/watermelonpgp.env`](../contrib/systemd/watermelonpgp.env).
`systemctl reload watermelonpgp` reloads the TLS certificate; other changes need a restart.
On stop, running jobs finish their current file first.

## Docker

The image runs as uid/gid `10001`, keeps its data in `/data`, listens on port 8080 and logs JSON.

```sh
docker build -t watermelon-pgp .          # or use ghcr.io/tarannum22/watermelon-pgp

# Once: database, master key and admin password
docker run --rm -it -v watermelonpgp-data:/data \
    -v /srv/watermelonpgp-key:/key -e WATERMELONPGP_MASTER_KEY_FILE=/key/master.key \
    watermelon-pgp init

docker run -d --name watermelonpgp --restart unless-stopped \
    -p 127.0.0.1:8080:8080 \
    -v watermelonpgp-data:/data \
    -v /srv/watermelonpgp-key:/key:ro -e WATERMELONPGP_MASTER_KEY_FILE=/key/master.key \
    -v /srv/sftp:/srv/sftp \
    watermelon-pgp
```

- Mount job folders at the **same path** inside the container, so the paths you enter in the UI
  are the real ones, and make them writable for uid `10001` (e.g. a shared group, as above, with
  `--group-add <gid>`).
- `/srv/watermelonpgp-key` must be owned by uid `10001` and not readable by others. Docker/Compose
  secrets are usually mounted world-readable and are refused; pass the key through
  `WATERMELONPGP_MASTER_KEY` instead if that's what your platform offers.
- Publish the port on `127.0.0.1` unless TLS is set up (next section).
- `docker stop` lets running jobs finish their current file; give it time with `--stop-timeout`
  if you process very large files.

## HTTPS

The UI must be reached over HTTPS once it leaves the machine: it handles the admin password and
secret-key exports. Two ways:

**Built in.** Give WatermelonPGP a certificate and key (PEM):

```sh
WATERMELONPGP_BIND=0.0.0.0:8443
WATERMELONPGP_TLS_CERT=/etc/watermelonpgp/tls/fullchain.pem
WATERMELONPGP_TLS_KEY=/etc/watermelonpgp/tls/privkey.pem
```

Session cookies are then marked `Secure` and HSTS is sent. After renewing the certificate, send
`SIGHUP` (`systemctl reload watermelonpgp`, `docker kill -s HUP watermelonpgp`): new connections use
the new certificate, no restart needed. On Windows, see [HTTPS on Windows](#https-on-windows).

**Behind a reverse proxy.** Keep WatermelonPGP on `127.0.0.1:8080`, terminate TLS in the proxy,
and set `WATERMELONPGP_SECURE_COOKIES=true`. The proxy must pass the `Host` header through
unchanged (form submissions are checked against it). Caddy:

```
pgp.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

Behind a proxy every request appears to come from the proxy's address, so the login rate limit
applies to all clients together. With a single admin account that is acceptable.

## Logs and monitoring

- `WATERMELONPGP_LOG_FORMAT=json` writes one JSON object per line to stderr; `text` is the default.
- `WATERMELONPGP_LOG=debug` (or `warn`, `error`) changes the level; the default is `info`.
- `WATERMELONPGP_LOG_FILE` (`--log-file`) appends the log to a file instead of stderr. The Windows
  service always logs to a file ([below](#the-windows-service)).
- `GET /healthz` returns `200 {"status":"ok"}` when the database is reachable, `503` otherwise.
  It needs no login.
- Logged: every page request (method, path, status, duration, client), job passes that
  processed or failed files, paused jobs, and errors. The full record of who did what is the
  audit log, in the UI or with `watermelonpgp audit`.

## Backups and restore

```sh
watermelonpgp backup /backups/watermelonpgp-$(date +%F).db
```

writes a consistent snapshot of the database while the service is running. It does **not**
include the master key, by design.

To restore: stop the service, delete `watermelonpgp.db-wal` and `watermelonpgp.db-shm` from the data
directory if present (they belong to the old database and would corrupt the restored one),
copy the snapshot to `<data dir>/watermelonpgp.db` (owned by the service user, mode `0600`), and
start the service with the **same master key**. WatermelonPGP checks at startup that the key
matches the database and refuses to start otherwise.

## Upgrading

Stop the service, replace the binary (or pull the new image), start it again. Database schema
migrations run automatically at startup.

Before migrating, WatermelonPGP copies the database as it was to
`<data dir>/watermelonpgp.db.schema-v<N>.bak`, where N is the old schema version. Older releases
can't open a migrated database, so to go back: stop the service, put the old binary back, and
restore that copy as described above. Delete the copy once you're happy with the new version;
like the database, it contains your keys (sealed under the master key).

`watermelonpgp backup` run with the *new* binary migrates the database before it copies it, so
for a backup the old release can read, run it with the old binary, before replacing it.

### From 0.3: `watermelon` is now `watermelonpgp`

The command was renamed to match the product, and everything named after it followed:

| 0.3 | Now |
|---|---|
| `watermelon` / `watermelon.exe` | `watermelonpgp` / `watermelonpgp.exe` |
| `WATERMELON_*` environment variables | `WATERMELONPGP_*` |
| `<data dir>/watermelon.db` | `<data dir>/watermelonpgp.db` (renamed automatically, see below) |
| `<data dir>\watermelon.log` (Windows service) | `<data dir>\watermelonpgp.log` |
| systemd unit, user and group `watermelon`, `/var/lib/watermelon`, `/etc/watermelon` | `watermelonpgp`, `/var/lib/watermelonpgp`, `/etc/watermelonpgp` |
| Docker user and group `watermelon` (uid/gid `10001`) | `watermelonpgp` (still `10001`) |
| Homebrew data directory `$(brew --prefix)/var/watermelon` | `$(brew --prefix)/var/watermelonpgp` |
| Windows service `watermelon`, account `NT SERVICE\watermelon` | `watermelonpgp`, `NT SERVICE\watermelonpgp` |

- **The database** keeps its data: the first command run on a data directory renames
  `watermelon.db` (and its `-wal` and `-shm` files) to `watermelonpgp.db`. It refuses to start if
  both names exist; keep the one you use. Upgrade snapshots taken by 0.3
  (`watermelon.db.schema-v<N>.bak`) keep their names. The master key is unchanged.
- **Environment variables:** `watermelonpgp` refuses to start while any `WATERMELON_*` variable is
  set, and names its replacement, so a setting such as `WATERMELON_TLS_CERT` can't be dropped
  without notice. Rename them wherever they're set: the systemd env file, `docker run -e`, a
  Compose file, a secret store, the Windows service's registry `Environment`.

**systemd.** Move everything to the new names, then install the new unit
([systemd](#systemd)):

```sh
sudo systemctl disable --now watermelon
sudo install -m 0755 watermelonpgp /usr/local/bin/watermelonpgp
sudo rm /usr/local/bin/watermelon /etc/systemd/system/watermelon.service
sudo mv /var/lib/watermelon /var/lib/watermelonpgp
sudo mv /etc/watermelon /etc/watermelonpgp
sudo mv /etc/watermelonpgp/watermelon.env /etc/watermelonpgp/watermelonpgp.env
sudo sed -i 's/WATERMELON_/WATERMELONPGP_/g; s#/etc/watermelon/#/etc/watermelonpgp/#g; s#/var/lib/watermelon\b#/var/lib/watermelonpgp#g' \
    /etc/watermelonpgp/watermelonpgp.env
sudo groupmod -n watermelonpgp watermelon
sudo usermod -l watermelonpgp -d /var/lib/watermelonpgp watermelon
# Your ReadWritePaths= drop-in, if any (check it for /var/lib/watermelon and /etc/watermelon too):
sudo mv /etc/systemd/system/watermelon.service.d /etc/systemd/system/watermelonpgp.service.d
sudo install -m 0644 contrib/systemd/watermelonpgp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now watermelonpgp
```

The renamed user keeps its uid, so job folders shared through a group or owned by it need no
change. Check your own unit overrides and scripts for `watermelon` paths.

**Docker.** Same image, and keep your existing volume (the examples above now call a new one
`watermelonpgp-data`; the name is yours to choose): the user keeps uid `10001`. Rename the
`-e WATERMELON_*` variables to `WATERMELONPGP_*`.

**Homebrew.** Move the data directory before starting the upgraded service:

```sh
brew services stop watermelon-pgp
brew upgrade watermelon-pgp
mv "$(brew --prefix)/var/watermelon" "$(brew --prefix)/var/watermelonpgp"
brew services start watermelon-pgp
```

The log is now `$(brew --prefix)/var/log/watermelonpgp.log`; delete the old `watermelon.log` when
you no longer need it.

**Windows.** A service keeps running the program it was installed with, so remove the old
service with the *old* program first, then install the new one with the same options (your
`--bind`, TLS and log settings) and grant the new account your job folders and anything else you
granted `NT SERVICE\watermelon`:

```powershell
watermelon service uninstall               # 0.3's watermelon.exe; data and key stay
# Install: choco install watermelon-pgp, or replace watermelon.exe with watermelonpgp.exe
# watermelonpgp refuses to start while a WATERMELON_* variable is set: clear them for good
# (if you set them machine-wide) and in this shell.
Get-ChildItem Env:WATERMELON_* | ForEach-Object {
  [Environment]::SetEnvironmentVariable($_.Name, $null, 'Machine')
  Remove-Item "Env:$($_.Name)"
}
$env:WATERMELONPGP_DATA_DIR = "C:\ProgramData\WatermelonPGP"
watermelonpgp service install --bind 127.0.0.1:8080
icacls D:\sftp /grant "NT SERVICE\watermelonpgp:(OI)(CI)M"
Start-Service watermelonpgp
```

`service install` hands the data directory and master key over to the new account. The
Chocolatey package refuses to install while a service still runs `watermelon.exe`, and removes
`watermelon.exe` once nothing does. The old `watermelon.log` stays in the data directory.

## Windows Server

WatermelonPGP runs natively on Windows Server (x86_64) as a Windows service; WSL2 is not needed.
CI tests it on Windows Server 2025. The commands below are for an **elevated** Windows
PowerShell ("Run as administrator"; the 5.1 that ships with Windows is enough). The layout used
here:

| What | Where |
|---|---|
| Program | `C:\Program Files\WatermelonPGP\watermelonpgp.exe` |
| Data directory | `C:\ProgramData\WatermelonPGP`, with the master key in it (`master.key`) |
| TLS certificate (optional) | `C:\ProgramData\WatermelonPGP-tls` |
| Service | `watermelonpgp`, running as `NT SERVICE\watermelonpgp` |

Another drive works the same way (e.g. `D:\WatermelonPGP`). The master key in the data
directory is the layout the Windows CI tests; to keep it elsewhere, see
[A master key outside the data directory](#a-master-key-outside-the-data-directory).

### Install

**With [Chocolatey](https://chocolatey.org/install)** (from an elevated PowerShell):

```powershell
choco install watermelon-pgp
```

The package downloads the release's zip from GitHub, checks it against the release's
`SHA256SUMS`, copies it into `C:\Program Files\WatermelonPGP` and adds that folder to the system
Path, so `watermelonpgp --version` works in a new shell. That's all it does: it doesn't run `init`
or `service install` and doesn't create or touch a data directory; those are the next steps,
below. A new version can take a few days to appear on Chocolatey after its GitHub release,
while the community repository reviews it; until then, install it from the zip.

- `choco upgrade watermelon-pgp`: if a Windows service runs
  `C:\Program Files\WatermelonPGP\watermelonpgp.exe`, the package stops it (running jobs finish
  their current file first), replaces the files and starts it again, which runs any database
  migration ([Backups and upgrades](#backups-and-upgrades)). A `watermelonpgp` running outside a
  service makes the upgrade fail; stop it and try again.
- `choco uninstall watermelon-pgp` refuses while a service for that program is installed. Run
  `watermelonpgp service uninstall` first, then uninstall again. It removes the program and its
  Path entry, and leaves the data directory and the master key; delete those yourself once
  you no longer need them.

**From the zip.** Windows releases start with 0.3.0. Download
`watermelon-pgp-vX.Y.Z-x86_64-pc-windows-msvc.zip` and `SHA256SUMS` from the
[GitHub releases](https://github.com/tarannum22/watermelon-pgp/releases), check the zip, and
unpack it into a folder of its own, named after the version:

```powershell
$name = "watermelon-pgp-vX.Y.Z-x86_64-pc-windows-msvc"
$expected = ((Get-Content SHA256SUMS) -match [regex]::Escape("$name.zip")) -split '\s+' | Select-Object -First 1
if ((Get-FileHash "$name.zip" -Algorithm SHA256).Hash -ne $expected) { throw "$name.zip does not match SHA256SUMS" }

Expand-Archive "$name.zip" -DestinationPath "$env:TEMP\$name"
New-Item -ItemType Directory "C:\Program Files\WatermelonPGP" -Force | Out-Null
Copy-Item "$env:TEMP\$name\$name\*" "C:\Program Files\WatermelonPGP" -Recurse -Force
$env:Path += ";C:\Program Files\WatermelonPGP"    # this shell; add it to the system Path to keep it
watermelonpgp --version
```

The zip holds `watermelonpgp.exe` with the C runtime linked in (no Visual C++ redistributable
needed), plus this documentation. `watermelonpgp.exe` isn't code-signed yet, so SmartScreen may
warn about it.

### The data directory and the master key

Every command works on a data directory: `.\data` relative to the current folder unless you
choose another with `--data-dir` or `WATERMELONPGP_DATA_DIR`. For a server, set it once for the
shell, then create the database, the master key and the admin password of the web UI:

```powershell
$env:WATERMELONPGP_DATA_DIR = "C:\ProgramData\WatermelonPGP"
watermelonpgp init      # prompts for the admin password
```

`init` creates the data directory (and any missing parent folder), the database and
`master.key` so that **only the account that ran it** can access them: their access lists don't
inherit from `C:\ProgramData`, which every local user can read. If the data directory already
exists and others can access it, `init` restricts it. `service install` then hands all of it to
the service account (next section).

The master key file is refused, the way Unix refuses one that isn't `0600`, if its access list
lets in anyone other than the account running WatermelonPGP, LocalSystem, Administrators and the
file's owner, or if the owner is anyone other than those or a service account
(`NT SERVICE\…`): an owner can always change the access list. The error says which `icacls`
commands fix it. `init` likewise refuses a data directory owned by another account. Because
Administrators and service-account owners count, an administrator can still run commands such
as `backup` and `audit` against the service's data from an elevated prompt.

Back the master key up once, somewhere safe and separate from the database backups. A copy
takes the access list of the folder it lands in, so restrict it to Administrators right away:

```powershell
Copy-Item C:\ProgramData\WatermelonPGP\master.key E:\keys\watermelonpgp-master.key
icacls E:\keys\watermelonpgp-master.key /inheritance:r /grant:r "BUILTIN\Administrators:F"
```

### The Windows service

After `init`, in the same elevated PowerShell (so `WATERMELONPGP_DATA_DIR` still applies), install
the service with the installed `watermelonpgp.exe`, which the service will run from where it is.
It runs `serve`, so it takes the same options; add `--tls-cert`/`--tls-key` here for HTTPS
([below](#https-on-windows)). The options, what `install` changes and the restart and stop
timings are in [docs/cli.md](cli.md#service-install).

```powershell
watermelonpgp service install --bind 127.0.0.1:8080
icacls D:\sftp /grant "NT SERVICE\watermelonpgp:(OI)(CI)M"    # the job folders, see below
Start-Service watermelonpgp
(Invoke-WebRequest http://127.0.0.1:8080/healthz -UseBasicParsing).Content   # {"status":"ok"}
```

The service runs as the virtual account **`NT SERVICE\watermelonpgp`**: no password to manage,
and no rights beyond what you grant it. `install` makes it the owner of the data directory and
everything in it, with access for it, LocalSystem and Administrators only, and prints what else
it allowed it to use. It starts with Windows and is restarted if it fails. To change a setting,
uninstall and install again; the data stays.

If `install` fails after it created the service, it removes the service again, but ownership
and access-list changes it already made stay: the data directory may be owned by
`NT SERVICE\watermelonpgp`, in part or in full. Administrators keep access either way, so CLI
commands still work. Fix the cause and run `service install` again; it applies the hand-over to
everything again.

**Stopping.** `Stop-Service watermelonpgp` (and `Restart-Service`) let running jobs finish their
current file, as SIGTERM does on Linux, and the service tells Windows it is still stopping for
as long as a job makes progress. A file an OS shutdown cuts short is processed again from the
start after the next boot.

**Uninstalling.** `watermelonpgp service uninstall` stops the service the same way and removes it.
The data directory and master key stay, still owned by the service account; Administrators keep
access.

**Logs.** The service has no console; it appends its log to `<data dir>\watermelonpgp.log`, or the
file given with `--log-file` at install. Follow it from an elevated prompt:

```powershell
Get-Content C:\ProgramData\WatermelonPGP\watermelonpgp.log -Tail 50 -Wait
```

If the service doesn't start and the log says nothing, it may not have been able to open the
log file (see [docs/cli.md](cli.md#service-install) for when it leaves a note in the default
log). Windows records the exit code and the reason:

```powershell
sc.exe query watermelonpgp     # WIN32_EXIT_CODE / SERVICE_EXIT_CODE
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 20
```

The log file isn't rotated: watch its size, and to start a new one stop the service, rename the
file and start it again. `--log-format json` at install writes one JSON object per line. To
change the level, set `WATERMELONPGP_LOG` in the service's environment and restart:

```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\watermelonpgp -Name Environment `
    -Type MultiString -Value "WATERMELONPGP_LOG=debug"
Restart-Service watermelonpgp
```

Don't put `WATERMELONPGP_MASTER_KEY` there: it would override the key file. `GET /healthz` works
as on Linux (see [Logs and monitoring](#logs-and-monitoring)).

### A master key outside the data directory

To keep the key apart from the data, as recommended in [The master key](#the-master-key), put
it in a folder of its own, e.g. `C:\ProgramData\WatermelonPGP-key`, and pass it to both
commands:

```powershell
$env:WATERMELONPGP_DATA_DIR = "C:\ProgramData\WatermelonPGP"
$env:WATERMELONPGP_MASTER_KEY_FILE = "C:\ProgramData\WatermelonPGP-key\master.key"
watermelonpgp init
watermelonpgp service install --bind 127.0.0.1:8080
icacls C:\ProgramData\WatermelonPGP-key /grant "NT SERVICE\watermelonpgp:(RX)"
```

`install` hands the key **file** to the service account, but not its folder: `init` creates
that folder (and every missing parent) private to you. The service then reaches the key only
through Windows' "Bypass traverse checking" right, which a security policy can remove, and
this layout isn't tested in CI. The last command grants the service account access to the
folder itself (no `(OI)(CI)`, so nothing inside inherits it). Do the same for every folder
`init` created on the way, if there are more.

### Job folders

The service account needs to read, write and delete in every job's input, output, `processed\`
and `failed\` folders (`processed\` and `failed\` are created if missing). Grant it on the folder
your SFTP server writes into; `(OI)(CI)` passes it on to files and subfolders:

```powershell
icacls D:\sftp /grant "NT SERVICE\watermelonpgp:(OI)(CI)M"
```

Folders are entered as drive paths (`D:\sftp\acme\in`) or UNC paths
(`\\fileserver\sftp\acme\in`), on the job form or with `watermelonpgp job add`.

- **Network shares:** a virtual account such as `NT SERVICE\watermelonpgp` reaches other machines as
  the server's **computer account**, `DOMAIN\HOST$`. Grant that account change access on the
  share and modify access on its folders. On a server that isn't in a domain, the computer
  account has no identity on the network, so shares that need a login don't work.
  `service install` can't run the service as a domain account or gMSA yet (see
  [Known limits](#known-limits)).
- **Mapped drive letters** (`Z:\`) belong to a user's logon session; the service doesn't see
  them. Use the UNC path.
- **Uploads in progress:** besides waiting until a file's size and modification time stop
  changing, a job leaves a file alone while another program (the SFTP server) still has it open
  for writing, without logging it as failed, and picks it up once it's closed. While a file is
  being processed, others can read it but not change or delete it.
- **Hidden files:** files with the *hidden* or *system* attribute (`Thumbs.db`, `desktop.ini`)
  are ignored, like names starting with a dot and the usual temporary upload names (`*.part`,
  `*.filepart`, `*.tmp`, `*.crdownload`, `*.partial`).
- **Output being written** goes to a temporary file in the output folder,
  `.<name>.<pid>-<n>.watermelon-tmp`, which is renamed to its final name once complete. On
  Windows it isn't marked hidden, so a process that collects files from the output folder
  should ignore names ending in `.watermelon-tmp` (or starting with a dot). Temporary files
  left by a crash are removed after 15 minutes.

### HTTPS on Windows

Keep the PEM certificate chain and key in a folder **outside** the data directory, which is
private to the service. The folder must be writable by whatever renews the certificate
(win-acme runs as LocalSystem) and readable by the service, and nobody else should read the
key. Create it with that access list before you install the service:

```powershell
New-Item -ItemType Directory C:\ProgramData\WatermelonPGP-tls | Out-Null
icacls C:\ProgramData\WatermelonPGP-tls /inheritance:r /grant:r `
    "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F"
```

Put the certificate files there and install the service with them (see [HTTPS](#https) for what
changes; if it's already installed, `watermelonpgp service uninstall` first):

```powershell
watermelonpgp service install --bind 0.0.0.0:8443 `
    --tls-cert C:\ProgramData\WatermelonPGP-tls\fullchain.pem `
    --tls-key C:\ProgramData\WatermelonPGP-tls\privkey.pem
icacls C:\ProgramData\WatermelonPGP-tls /grant "NT SERVICE\watermelonpgp:(OI)(CI)R"
```

`install` lets the service account read the two files as they are. The last command grants it
on the folder too, so files a renewal writes anew inherit it. After renewing, reload the
certificate without a restart:

```powershell
sc.exe control watermelonpgp paramchange
```

With [win-acme](https://www.win-acme.com/), store the certificate as PEM files in that folder
and run that command as the installation step after each renewal.

To bind beyond loopback, as above, allow the port in Windows Firewall:

```powershell
New-NetFirewallRule -DisplayName "WatermelonPGP" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### Backups and upgrades

From an elevated prompt, an administrator can back up the database while the service runs:

```powershell
watermelonpgp --data-dir C:\ProgramData\WatermelonPGP backup "D:\backups\watermelonpgp-$(Get-Date -Format yyyy-MM-dd).db"
```

The copy is readable only by you. As on Linux, it doesn't include the master key; back that up
separately ([above](#the-data-directory-and-the-master-key)).

To restore: `Stop-Service watermelonpgp`, delete `watermelonpgp.db-wal` and `watermelonpgp.db-shm` from
the data directory if present, copy the snapshot to `<data dir>\watermelonpgp.db`, give it the
data directory's access list, and start the service with the same master key:

```powershell
Copy-Item D:\backups\watermelonpgp-2026-11-25.db C:\ProgramData\WatermelonPGP\watermelonpgp.db
icacls C:\ProgramData\WatermelonPGP\watermelonpgp.db /reset
Start-Service watermelonpgp
```

`icacls /reset` replaces the file's access list with the one it inherits from the data
directory (the service account, LocalSystem and Administrators). Without it, a file moved in
from the same volume keeps the private access list of the backup, and the service can't open
it. Uninstalling and installing the service again also works: `install` re-applies its
hand-over to everything in the data directory.

To upgrade from 0.3, follow [From 0.3](#from-03-watermelon-is-now-watermelonpgp) first. To upgrade: with Chocolatey, `choco upgrade watermelon-pgp`, which stops the service,
replaces the program and starts it again ([Install](#install)). From the zip: unpack the new
zip into its own folder as in [Install](#install), then `Stop-Service watermelonpgp`, copy the new
`watermelonpgp.exe` over the old one in `C:\Program Files\WatermelonPGP`, and
`Start-Service watermelonpgp`. As described in
[Upgrading](#upgrading), a database upgrade first keeps a copy of the old database in the data
directory (`watermelonpgp.db.schema-v<N>.bak`); for a backup the old release can read, run
`backup` with the old program (`watermelon.exe` for 0.3) before replacing it (or before `choco upgrade`).

### Known limits

- The service runs as its virtual account (`NT SERVICE\<name>`) only; a custom, domain or
  group-managed service account isn't supported yet, so network shares must allow the computer
  account.
- To change a setting of an installed service, uninstall and install it again.
- No jobs-only service (`run`): the service always serves the web UI too.
- The log is a plain file without rotation; nothing goes to the Event Log.
- An OS shutdown can stop the service before a large file is finished; the file is processed
  again from the start on the next start.
- The TLS certificate comes from PEM files, not the Windows certificate store.
- Temporary output files aren't hidden (see [Job folders](#job-folders)).
- `watermelonpgp.exe` isn't code-signed, and there's no installer, winget or Scoop package yet.
- x86_64 only. CI tests Windows Server 2025; Server 2022 isn't tested.
